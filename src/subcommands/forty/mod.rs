use crate::utils::index::IndexController;
use crate::utils::other::{
    get_max_mature_number, get_network_type, get_privkey_signer, is_mature, read_password,
    serialize_signature,
};
use byteorder::{ByteOrder, LittleEndian};
use ckb_hash::new_blake2b;
use ckb_index::{with_index_db, IndexDatabase, LiveCellInfo};
use ckb_jsonrpc_types::JsonBytes;
use ckb_sdk::{constants::{MIN_SECP_CELL_CAPACITY, SIGHASH_TYPE_HASH}, wallet::KeyStore, GenesisInfo, HttpRpcClient, SignerFn, Address};
use ckb_types::{
    bytes::Bytes,
    core::{ScriptHashType, TransactionView},
    packed::{Byte32, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
    {h256, H160, H256},
};
use itertools::Itertools;
use std::collections::HashSet;
use std::path::PathBuf;
pub use crate::subcommands::forty::command::{IssueArgs, TransactArgs};
pub use crate::utils::arg_parser::PrivkeyWrapper;
pub use crate::subcommands::forty::builder::FortyBuilder;
use ckb_types::packed::CellDep;
use crate::subcommands::dao::take_by_out_points;

pub mod builder;
pub mod command;
pub mod util;

// TODO 之后改掉。这里只是为了保证之后的操作有足够的 fee，偷个懒
const MIN_FT_CELL_CAPACITY: u64 = MIN_SECP_CELL_CAPACITY + 100 * 100;
const TX_FEE: u64 = 1000;

pub struct FortySubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    key_store: &'a mut KeyStore,
    genesis_info: GenesisInfo,
    index_dir: PathBuf,
    index_controller: IndexController,
    issue_args: Option<IssueArgs>,
    transact_args: Option<TransactArgs>,
}

impl<'a> FortySubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        key_store: &'a mut KeyStore,
        genesis_info: GenesisInfo,
        index_dir: PathBuf,
        index_controller: IndexController,
    ) -> Self {
        Self {
            rpc_client,
            key_store,
            genesis_info,
            index_dir,
            index_controller,
            issue_args: None,
            transact_args: None,
        }
    }

    // Issue, traditional sighash cell => FT cell
    pub fn issue(&mut self) -> Result<TransactionView, String> {
        self.check_db_ready()?;
        let target_ckb_capacity = 2 * MIN_FT_CELL_CAPACITY + TX_FEE;
        let sender_address = self.issue_args().sender_address().clone();
        let cells = self.collect_sighash_cells(sender_address, target_ckb_capacity)?;
        let raw_transaction = self.build(cells).issue(
            self.issue_args.as_ref().unwrap())?;
        self.sign(raw_transaction)
    }

    // NOTE: Assume the FT cell has enough capacity to pay for tx-fee(Archive this by set the
    // `MIN_FT_CELL_CAPACITY` highly).
    //
    // Transfer, FT cell => FT cell
    pub fn transfer(&mut self) -> Result<TransactionView, String> {
        self.check_db_ready()?;
        let out_point = self.transact_args().out_point.clone();
        let out_points = vec![out_point];

        let ft_cells = self.collect_sender_ft_cells()?;
        let ft_cells = take_by_out_points(ft_cells, &out_points)?;
        // let raw_transaction = self.build(ft_cells).transfer(&self.transact_args.unwrap())?;
        // FIXME 这里先 mock proof 了
        let raw_transaction = self.build(ft_cells).transfer(
            self.transact_args.as_ref().unwrap(), self.transact_args().proof())?;
        self.sign(raw_transaction)
    }

    pub fn collect_sender_ft_cells(&mut self) -> Result<Vec<LiveCellInfo>, String>{
        let ft_code_hash = self.ft_code_hash();
        let lock_hash = self.sender_lock_hash();
        self.with_db(|db, _| {
            let cells_by_lock = db
                .get_live_cells_by_lock(lock_hash, Some(0), |_, _| (false, true))
                .into_iter()
                .collect::<HashSet<_>>();
            let cells_by_code = db
                .get_live_cells_by_code(ft_code_hash.clone(), Some(0), |_, _| (false, true))
                .into_iter()
                .collect::<HashSet<_>>();
            cells_by_lock
                .intersection(&cells_by_code)
                .sorted_by_key(|live| (live.number, live.tx_index, live.index.output_index))
                .cloned()
                .collect::<Vec<_>>()
        })
    }

    pub fn build(&self, cells: Vec<LiveCellInfo>) -> FortyBuilder {
        FortyBuilder::new(self.genesis_info.clone(), TX_FEE, cells)
    }

    fn check_db_ready(&mut self) -> Result<(), String> {
        self.with_db(|_, _| ())
    }

    fn with_db<F, T>(&mut self, func: F) -> Result<T, String>
        where
            F: FnOnce(IndexDatabase, &mut HttpRpcClient) -> T,
    {
        let network_type = get_network_type(self.rpc_client)?;
        let genesis_info = self.genesis_info.clone();
        let genesis_hash: H256 = genesis_info.header().hash().unpack();
        with_index_db(&self.index_dir.clone(), genesis_hash, |backend, cf| {
            let db = IndexDatabase::from_db(backend, cf, network_type, genesis_info, false)?;
            Ok(func(db, self.rpc_client()))
        })
            .map_err(|_err| {
                format!(
                    "Index database may not ready, sync process: {}",
                    self.index_controller.state().read().to_string()
                )
            })
    }

    fn sign(&mut self, transaction: TransactionView) -> Result<TransactionView, String> {
        // 1. Install sighash lock script
        let transaction = self.install_receiver_sighash_lock(transaction);

        // 2. Install signed sighash witnesses
        let transaction = self.install_sender_sighash_witness(transaction)?;

        Ok(transaction)
    }

    // Install receiver's lock to defend output cells
    fn install_receiver_sighash_lock(&self, transaction: TransactionView) -> TransactionView {
        let sighash_args = self.receiver_sighash_args();
        let genesis_info = &self.genesis_info;
        let sighash_dep = genesis_info.sighash_dep();
        let sighash_type_hash = genesis_info.sighash_type_hash();
        let lock_script = Script::new_builder()
            .hash_type(ScriptHashType::Type.into())
            .code_hash(sighash_type_hash.clone())
            .args(Bytes::from(sighash_args.as_bytes().to_vec()).pack())
            .build();
        let outputs = transaction
            .outputs()
            .into_iter()
            .map(|output: CellOutput| output.as_builder().lock(lock_script.clone()).build())
            .collect::<Vec<_>>();
        transaction
            .as_advanced_builder()
            .set_outputs(outputs)
            .cell_dep(sighash_dep)
            .build()
    }

    // Install sender's witness to unlock the input cells
    fn install_sender_sighash_witness(
        &self,
        transaction: TransactionView,
    ) -> Result<TransactionView, String> {
        for output in transaction.outputs() {
            assert_eq!(output.lock().hash_type(), ScriptHashType::Type.into());
            assert_eq!(output.lock().args().len(), 20);
            assert_eq!(output.lock().code_hash(), SIGHASH_TYPE_HASH.pack());
        }
        for witness in transaction.witnesses() {
            if let Ok(w) = WitnessArgs::from_slice(witness.as_slice()) {
                assert!(w.lock().is_none());
            }
        }

        let mut witnesses = transaction
            .witnesses()
            .into_iter()
            .map(|w| w.unpack())
            .collect::<Vec<Bytes>>();
        let init_witness = {
            let init_witness = if witnesses[0].is_empty() {
                WitnessArgs::default()
            } else {
                WitnessArgs::from_slice(&witnesses[0]).map_err(|err| err.to_string())?
            };
            init_witness
                .as_builder()
                .lock(Some(Bytes::from(&[0u8; 65][..])).pack())
                .build()
        };
        let digest = {
            let mut blake2b = new_blake2b();
            blake2b.update(&transaction.hash().raw_data());
            blake2b.update(&(init_witness.as_bytes().len() as u64).to_le_bytes());
            blake2b.update(&init_witness.as_bytes());
            for other_witness in witnesses.iter().skip(1) {
                blake2b.update(&(other_witness.len() as u64).to_le_bytes());
                blake2b.update(&other_witness);
            }
            let mut message = [0u8; 32];
            blake2b.finalize(&mut message);
            H256::from(message)
        };
        let signature = {
            let sender_sighash_args = self.sender_sighash_args();
            let mut signer = {
                let privkey = self.sender_privkey();
                get_privkey_signer(privkey.clone())
            };
            let accounts = vec![sender_sighash_args].into_iter().collect::<HashSet<H160>>();
            signer(&accounts, &digest)?.expect("signer missed")
        };

        witnesses[0] = init_witness
            .as_builder()
            .lock(Some(Bytes::from(signature[..].to_vec())).pack())
            .build()
            .as_bytes();

        Ok(transaction
            .as_advanced_builder()
            .set_witnesses(witnesses.into_iter().map(|w| w.pack()).collect::<Vec<_>>())
            .build())
    }

    fn collect_sighash_cells(&mut self, address: Address, target_capacity: u64) -> Result<Vec<LiveCellInfo>, String> {
        let mut enough = false;
        let mut take_capacity = 0;
        let max_mature_number = get_max_mature_number(self.rpc_client())?;
        let terminator = |_, cell: &LiveCellInfo| {
            if !(cell.type_hashes.is_none() && cell.data_bytes == 0)
                && is_mature(cell, max_mature_number)
            {
                return (false, false);
            }

            take_capacity += cell.capacity;
            if take_capacity == target_capacity
                || take_capacity >= target_capacity + MIN_SECP_CELL_CAPACITY
            {
                enough = true;
            }
            (enough, true)
        };

        let cells: Vec<LiveCellInfo> = {
            self.with_db(|db, _| {
                db.get_live_cells_by_lock(
                    Script::from(address.payload()).calc_script_hash(),
                    None,
                    terminator,
                )
            })?
        };

        if !enough {
            return Err("CKB Capacity not enough".to_string());
        }

        Ok(cells)
    }

    fn issue_args(&self) -> &IssueArgs {
        self.issue_args.as_ref().expect("exist")
    }

    fn transact_args(&self) -> &TransactArgs {
        self.transact_args.as_ref().expect("exist")
    }

    pub fn rpc_client(&mut self) -> &mut HttpRpcClient {
        &mut self.rpc_client
    }

    fn receiver_sighash_args(&self) -> H160 {
        if let Some(ref issue_args) = self.issue_args.as_ref() {
            issue_args.receiver_sighash_args()
        } else if let Some(transact_args) = self.transact_args.as_ref() {
            transact_args.receiver_sighash_args()
        } else {
            unreachable!()
        }
    }

    fn sender_sighash_args(&self) -> H160 {
        if let Some(ref issue_args) = self.issue_args.as_ref() {
            issue_args.sender_sighash_args()
        } else if let Some(transact_args) = self.transact_args.as_ref() {
            transact_args.sender_sighash_args()
        } else {
            unreachable!()
        }
    }

    fn sender_lock_hash(&self) -> Byte32 {
        if let Some(ref issue_args) = self.issue_args.as_ref() {
            issue_args.sender_lock_hash()
        } else if let Some(transact_args) = self.transact_args.as_ref() {
            transact_args.sender_lock_hash()
        } else {
            unreachable!()
        }
    }

    pub fn sender_privkey(&self) -> &PrivkeyWrapper {
        if let Some(ref issue_args) = self.issue_args.as_ref() {
            issue_args.sender_privkey()
        } else if let Some(transact_args) = self.transact_args.as_ref() {
            transact_args.sender_privkey()
        } else {
            unreachable!()
        }
    }

    pub fn ft_type_hash(&self) -> Byte32 {
        if let Some(ref issue_args) = self.issue_args.as_ref() {
            issue_args.ft_type_script().calc_script_hash()
        } else if let Some(transact_args) = self.transact_args.as_ref() {
            transact_args.ft_type_script().calc_script_hash()
        } else {
            unreachable!()
        }
    }

    pub fn ft_code_hash(&self) -> Byte32 {
        if let Some(ref issue_args) = self.issue_args.as_ref() {
            issue_args.ft_code_hash()
        } else if let Some(transact_args) = self.transact_args.as_ref() {
            transact_args.ft_code_hash()
        } else {
            unreachable!()
        }
    }
}
