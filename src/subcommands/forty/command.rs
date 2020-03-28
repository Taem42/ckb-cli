use crate::subcommands::{CliSubCommand, FortySubCommand};
use crate::utils::{
    arg,
    arg_parser::{
        AddressParser, ArgParser, CapacityParser, FixedHashParser, OutPointParser,
        PrivkeyPathParser, PrivkeyWrapper,
    },
    other::{get_address, get_network_type},
    printer::{OutputFormat, Printable},
};
use ckb_crypto::secp::{SECP256K1, Pubkey};
use ckb_sdk::{constants::SIGHASH_TYPE_HASH, Address, AddressPayload, NetworkType, HttpRpcClient};
use ckb_types::{
    packed::{Byte32, Script},
    prelude::*,
    H160, H256,
};
use clap::{App, Arg, ArgMatches, SubCommand};
use std::collections::HashSet;
use ckb_types::packed::{OutPoint, Bytes, BytesVec, CellDep};
use crate::utils::arg_parser::PubkeyHexParser;
use secp256k1::PublicKey;
use sha2::Digest;
use crate::utils::other::serialize_signature;
use crate::subcommands::forty::util::send_transaction;
use ckb_types::core::ScriptHashType;

impl<'a> CliSubCommand for FortySubCommand<'a> {
    fn process(
        &mut self,
        matches: &ArgMatches,
        format: OutputFormat,
        color: bool,
        debug: bool,
    ) -> Result<String, String> {
        let network_type = get_network_type(&mut self.rpc_client)?;
        match matches.subcommand() {
            ("issue", Some(m)) => {
                self.issue_args = Some(IssueArgs::from_matches(m, network_type)?);
                let transaction = self.issue()?;

                let tx_hash = transaction.hash();
                println!(
                    "./target/release/ckb-cli --wait-for-sync forty transfer --ft-code-hash {:#x} --ft-out-point {:#x}-0 --amount-hash 97490a5ee735719234aa0317a44d2e8962e76fe3273bb79124de4053dc4a2434 --privkey-path /Users/apple/ckb-testing/bank0 --ft-lock-hash {:#x} --out-point {:#x}-0 --pubkey 020563b349c7b4c4cf9f100c50cd6de400098542e4cab07a86af0bd6414a58258a --proof 2de36a5b987c89b3b7de96a5d9563fccde1e5f9358371b098ec589c9ead54355867db0d4b674f3cd6b2f34b2266aec200a040f5beb80a5c1530262b27492d4911754b93046554fb44e9c871e4958e8461805c111ea5b000a01e35b076f74f7101d4cdf729302fbe4bdda37e17faaa9c81c5ac37bc1bbbefa71b0579fdffacfe8",
                    self.issue_args().ft_code_hash(),
                    self.issue_args().ft_out_point.tx_hash(),
                    self.issue_args().ft_lock_hash(),
                    tx_hash,
                );

                send_transaction(self.rpc_client(), transaction, format, color, debug)
            }
            ("transfer", Some(m)) => {
                self.transact_args = Some(TransactArgs::from_matches(m, network_type)?);
                let transaction = self.transfer()?;
                send_transaction(self.rpc_client(), transaction, format, color, debug)
            }
//            ("query", Some(m)) => {
//                let query_args = QueryArgs::from_matches(m, network_type)?;
//                let lock_hash = query_args.lock_hash;
//                let cells = self.query_prepare_cells(lock_hash)?;
//                let resp = serde_json::json!({
//                    "live_cells": (0..cells.len()).map(|i| {
//                        let mut value = serde_json::to_value(&cells[i]).unwrap();
//                        let obj = value.as_object_mut().unwrap();
//                        obj.insert("maximum_withdraw".to_owned(), serde_json::json!(maximum_withdraws[i]));
//                        value
//                    }).collect::<Vec<_>>(),
//                });
//                Ok(resp.render(format, color))
//            }
            _ => Err(matches.usage().to_owned()),
        }
    }
}

impl<'a> FortySubCommand<'a> {
    pub fn subcommand() -> App<'static, 'static> {
        SubCommand::with_name("forty")
            .about("FortyToken operations")
            .subcommand(
                SubCommand::with_name("issue")
                    .about("Issue FT to admin self")
                    .arg(arg::privkey_path().required_unless(arg::from_account().b.name))
                    .arg(arg::ft_out_point().required(true))
                    .arg(arg::amount_hash().required(true))
                    .arg(arg::ft_code_hash().required(true))
        )
            .subcommand(
                SubCommand::with_name("transfer")
                    .about("Transfer FT")
                    .arg(arg::privkey_path().required(true))
                    .arg(arg::ft_out_point().required(true))
                    .arg(arg::out_point().required(true))
                    .arg(arg::pubkey().required(true))
                    .arg(arg::amount_hash().required(true))
                    .arg(arg::proof().required(true))
                    .arg(arg::ft_code_hash().required(true))
                    .arg(arg::ft_lock_hash().required(true))
        )
    }
}

//pub struct QueryArgs {
//    pub lock_hash: Byte32,
//}

// TODO ft_code_hash can be fetch vis RPC
pub struct IssueArgs {
    pub network_type: NetworkType,
    pub sender: PrivkeyWrapper,
    pub amount_hash: Byte32,
    pub ft_out_point: OutPoint,
    pub ft_code_hash: Byte32,
}

pub struct TransactArgs {
    pub network_type: NetworkType,
    pub sender: PrivkeyWrapper,
    pub receiver: PublicKey,
    pub amount_hash: Byte32,
    pub proof: Bytes,
    pub out_point: OutPoint,
    pub ft_out_point: OutPoint,
    pub ft_code_hash: Byte32,
    pub ft_lock_hash: Byte32,
}

impl IssueArgs {
    fn from_matches(m: &ArgMatches, network_type: NetworkType) -> Result<Self, String> {
        let sender: PrivkeyWrapper =
            PrivkeyPathParser.from_matches_opt(m, "privkey-path", true)?.unwrap();
        let ft_out_point: OutPoint = OutPointParser.from_matches(m, "ft-out-point")?;
        let ft_code_hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "ft-code-hash")?;
        let amount_hash: H256 = FixedHashParser::<H256>::default().from_matches(m, "amount-hash")?;

        Ok(Self {
            network_type,
            ft_out_point,
            ft_code_hash: Byte32::new(ft_code_hash.0),
            sender,
            amount_hash: Byte32::new(amount_hash.0),
        })
    }

    pub fn sender_privkey(&self) -> &PrivkeyWrapper {
        &self.sender
    }

    pub fn receiver_address(&self) -> Address {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &self.sender);
        let payload = AddressPayload::from_pubkey(&pubkey);
        Address::new(self.network_type, payload)
    }

    pub fn receiver_sighash_args(&self) -> H160 {
        H160::from_slice(self.receiver_address().payload().args().as_ref()).unwrap()
    }

    pub fn receiver_lock_hash(&self) -> Byte32 {
        Script::from(self.receiver_address().payload()).calc_script_hash()
    }

    pub fn amount_hash(&self) -> Byte32 {
        self.amount_hash.clone()
//        let mut hasher = sha2::Sha256::new();
//        let preimage = format!("{},{}", self.amount, self.nonce);
//        hasher.input(preimage.as_bytes());
//        let result = hasher.result();
//
//        let hash = Byte32::from_slice(
//            result.as_slice()
//        ).unwrap();
//
//        hash
    }

    // encrypted_amount = receiver.pubkey.sign_recoverable()
    pub fn encrypted_amount(&self) -> Bytes {
        // As for command "issue", the sender and receiver are the same.
//        let receiver = &self.sender;

        //let preimage = format!("{},{}", self.amount, self.nonce);
        //preimage.pack()
        Default::default()
//        let message = secp256k1::Message::from_slice(preimage.as_bytes())
//            .expect("Failed to convert FT preimage to secp256k1 message");
//
//        // FIXME 我不知道如何用 pubkey 加密 preimage，先留个FIXME，先折腾其它的
//        let builder: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
//        let signature = builder.sign_recoverable(&message, receiver);
//        let serialized_signature = serialize_signature(&signature);
//        serialized_signature.pack()
    }

    pub fn ft_output_data(&self) -> Bytes {
        BytesVec::new_builder()
            .push(self.amount_hash().as_bytes().pack())
            // .push(self.encrypted_amount())
            .build()
            .as_bytes()
            .pack()
    }

    // 只有 IssueArgs 有 ft_lock_hash()，因为可以从 privkey 里推导出来
    // 至于 TransactArgs，那应该从 input 的 type_script.args 里拿出来（其实直接拷贝整个 type_script 即可）
    pub fn ft_lock_hash(&self) -> Byte32 {
        self.sender_lock_hash()
    }

    pub fn ft_code_hash(&self) -> Byte32 {
        self.ft_code_hash.clone()
    }

    pub fn ft_type_script(&self) -> Script {
        let ft_code_hash = self.ft_code_hash();
        let ft_lock_hash = self.ft_lock_hash();
        Script::new_builder()
            .hash_type(ScriptHashType::Data.into())
            .code_hash(ft_code_hash)
            .args(ft_lock_hash.as_bytes().pack())
            .build()
    }

    pub fn sender_address(&self) -> Address {
        self.receiver_address()
    }

    pub fn sender_sighash_args(&self) -> H160 {
        self.receiver_sighash_args()
    }

    pub fn sender_lock_hash(&self) -> Byte32 {
        self.receiver_lock_hash()
    }

    pub fn ft_cell_dep(&self) -> CellDep {
        CellDep::new_builder()
            .out_point(self.ft_out_point.clone())
            .build()
    }
}

impl TransactArgs {
    fn from_matches(m: &ArgMatches, network_type: NetworkType) -> Result<Self, String> {
        let ft_out_point: OutPoint = OutPointParser
            .from_matches(m, "ft-out-point")?;
        let sender: PrivkeyWrapper =
            PrivkeyPathParser.from_matches(m, "privkey-path")?;
        let receiver = PubkeyHexParser.from_matches(m, "pubkey").unwrap();
        let out_point: OutPoint = OutPointParser.from_matches(m, "out-point")?;
        let ft_code_hash: H256 = FixedHashParser::<H256>::default().from_matches(
            m, "ft-code-hash")?;
        let ft_lock_hash: H256 = FixedHashParser::<H256>::default().from_matches(
            m, "ft-lock-hash")?;
        let amount_hash: H256 = FixedHashParser::<H256>::default().from_matches(
            m, "amount-hash")?;
        let proof: Bytes = m.value_of("proof").expect("expect proof").pack();
        Ok(Self {
            network_type,
            sender,
            receiver,
            proof,
            out_point,
            ft_out_point,
            ft_code_hash: Byte32::new(ft_code_hash.0),
            ft_lock_hash: Byte32::new(ft_lock_hash.0),
            amount_hash: Byte32::new(amount_hash.0),
        })
    }

    pub fn proof(&self) -> Bytes {
        self.proof.clone()
    }

    pub fn sender_privkey(&self) -> &PrivkeyWrapper {
        &self.sender
    }

    pub fn receiver_address(&self) -> Address {
        let payload = AddressPayload::from_pubkey(&self.receiver);
        Address::new(self.network_type, payload)
    }

    pub fn receiver_sighash_args(&self) -> H160 {
        H160::from_slice(self.receiver_address().payload().args().as_ref()).unwrap()
    }

    pub fn receiver_lock_hash(&self) -> Byte32 {
        Script::from(self.receiver_address().payload()).calc_script_hash()
    }

    pub fn receiver_encrypt_amount(&self) {
    }

    pub fn sender_address(&self) -> Address {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &self.sender);
        let payload = AddressPayload::from_pubkey(&pubkey);
        Address::new(self.network_type, payload)
    }

    pub fn sender_sighash_args(&self) -> H160 {
        H160::from_slice(self.sender_address().payload().args().as_ref()).unwrap()
    }

    pub fn sender_lock_hash(&self) -> Byte32 {
        Script::from(self.sender_address().payload()).calc_script_hash()
    }

    pub fn amount_hash(&self) -> Byte32 {
        self.amount_hash.clone()
//        let mut hasher = sha2::Sha256::new();
//        let preimage = format!("{},{}", self.amount, self.nonce);
//        hasher.input(preimage.as_bytes());
//        let result = hasher.result();
//        let hash = Byte32::from_slice(
//            result.as_slice()
//        ).unwrap();
//
//        hash
    }

    // encrypted_amount = receiver.pubkey.sign_recoverable()
    pub fn encrypted_amount(&self) -> Bytes {
        // FIXME 我不知道如何用 pubkey 加密 preimage，先留个FIXME，先折腾其它的
        // As for command "issue", the sender and receiver are the same.
//        let receiver = &self.receiver;

        // let preimage = format!("{},{}", self.amount, self.nonce);
        // preimage.pack()
        Default::default()
//        let message = secp256k1::Message::from_slice(preimage.as_bytes())
//            .expect("Failed to convert FT preimage to secp256k1 message");
//
//        // FIXME 我不知道如何用 pubkey 加密 preimage，先留个FIXME，先折腾其它的
//        let builder: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
//        let signature = builder.sign_recoverable(&message, receiver);
//        let serialized_signature = serialize_signature(&signature);
//        serialized_signature.pack()
        // Bytes::from(serialized_signature[..].to_vec())
    }

    pub fn ft_output_data(&self) -> Bytes {
        BytesVec::new_builder()
            .push(self.amount_hash().as_bytes().pack())
            // .push(self.encrypted_amount())
            .build()
            .as_bytes()
            .pack()
    }

    pub fn ft_code_hash(&self) -> Byte32 {
        self.ft_code_hash.clone()
    }

    pub fn ft_lock_hash(&self) -> Byte32 {
        self.ft_lock_hash.clone()
    }

    pub fn ft_type_script(&self) -> Script {
        let ft_code_hash = self.ft_code_hash();
        let ft_lock_hash = self.ft_lock_hash();
        Script::new_builder()
            .hash_type(ScriptHashType::Data.into())
            .code_hash(ft_code_hash)
            .args(ft_lock_hash.as_bytes().pack())
            .build()
    }

    pub fn ft_cell_dep(&self) -> CellDep {
        CellDep::new_builder()
            .out_point(self.ft_out_point.clone())
            .build()
    }
}

//impl QueryArgs {
//    fn from_matches(m: &ArgMatches, network_type: NetworkType) -> Result<Self, String> {
//        let lock_hash_opt: Option<H256> =
//            FixedHashParser::<H256>::default().from_matches_opt(m, "lock-hash", false)?;
//        let lock_hash = if let Some(lock_hash) = lock_hash_opt {
//            lock_hash.pack()
//        } else {
//            let address = get_address(Some(network_type), m)?;
//            Script::from(&address).calc_script_hash()
//        };
//
//        Ok(Self { lock_hash })
//    }
//
//    fn args<'a, 'b>() -> Vec<Arg<'a, 'b>> {
//        vec![arg::lock_hash(), arg::address()]
//    }
//}
//
