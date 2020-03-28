use crate::utils::arg_parser::{
    AddressParser, ArgParser, CapacityParser, FilePathParser, FixedHashParser, FromStrParser,
    HexParser, OutPointParser, PrivkeyPathParser, PubkeyHexParser,
};
use ckb_types::{H160, H256};
use clap::Arg;

pub fn privkey_path<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("privkey-path")
        .long("privkey-path")
        .takes_value(true)
        .validator(|input| PrivkeyPathParser.validate(input))
        .help("Private key file path (only read first line)")
}

pub fn pubkey<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("pubkey")
        .long("pubkey")
        .takes_value(true)
        .validator(|input| PubkeyHexParser.validate(input))
        .help("Public key (hex string, compressed format)")
}

pub fn address<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("address")
        .long("address")
        .takes_value(true)
        .validator(|input| AddressParser::default().validate(input))
        .help(
            "Target address (see: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0021-ckb-address-format/0021-ckb-address-format.md)",
        )
}

pub fn lock_hash<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("lock-hash")
        .long("lock-hash")
        .takes_value(true)
        .validator(|input| FixedHashParser::<H256>::default().validate(input))
        .help("Lock hash")
}

pub fn derive_receiving_address_length<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("derive-receiving-address-length")
        .long("derive-receiving-address-length")
        .takes_value(true)
        .default_value("1000")
        .validator(|input| FromStrParser::<u32>::default().validate(input))
        .help("Search derived receiving address length")
}

pub fn derive_change_address_length<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("derive-change-address-length")
        .long("derive-change-address-length")
        .takes_value(true)
        .default_value("1000")
        .validator(|input| FromStrParser::<u32>::default().validate(input))
        .help("Search derived change address length")
}

pub fn derive_change_address<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("derive-change-address")
        .long("derive-change-address")
        .takes_value(true)
        .validator(|input| AddressParser::default().validate(input))
        .help("Manually specify the last change address (search 10000 addresses max, required keystore password, see: BIP-44)")
}

pub fn derived<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("derived")
        .long("derived")
        .help("Search derived address space (search 10000 addresses(change/receiving) max, required keystore password, see: BIP-44)")
}

pub fn lock_arg<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("lock-arg")
        .long("lock-arg")
        .takes_value(true)
        .validator(|input| FixedHashParser::<H160>::default().validate(input))
        .help("Lock argument (account identifier, blake2b(pubkey)[0..20])")
}

pub fn ft_lock_hash<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("ft-lock-hash")
        .long("ft-lock-hash")
        .takes_value(true)
        .validator(|input| FixedHashParser::<H256>::default().validate(input))
        .help("identifier of the token")
}

pub fn from_account<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("from-account")
        .long("from-account")
        .takes_value(true)
        .validator(|input| {
            FixedHashParser::<H160>::default()
                .validate(input.clone())
                .or_else(|err| {
                    AddressParser::default()
                        .validate(input.clone())
                        .and_then(|()| AddressParser::new_sighash().validate(input))
                        .map_err(|_| err)
                })
        })
        .help("The account's lock-arg or sighash address (transfer from this account)")
}

pub fn from_locked_address<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("from-locked-address")
        .long("from-locked-address")
        .takes_value(true)
        .validator(|input| AddressParser::default().validate(input))
        .help("The time locked multisig address to search live cells (which S=0,R=0,M=1,N=1 and have since value)")
}

pub fn to_address<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("to-address")
        .long("to-address")
        .takes_value(true)
        .validator(|input| AddressParser::default().validate(input))
        .help("Target address")
}

pub fn to_data<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("to-data")
        .long("to-data")
        .takes_value(true)
        .validator(|input| HexParser.validate(input))
        .help("Hex data store in target cell (optional)")
}

pub fn proof<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("proof")
        .long("proof")
        .takes_value(true)
        .validator(|input| HexParser.validate(input))
        .help("zk-proof")
}

pub fn to_data_path<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("to-data-path")
        .long("to-data-path")
        .takes_value(true)
        .validator(|input| FilePathParser::new(true).validate(input))
        .help("Data binary file path store in target cell (optional)")
}

//pub fn amount<'a, 'b>() -> Arg<'a, 'b> {
//    Arg::with_name("amount")
//        .long("amount")
//        .takes_value(true)
//        .validator(|input| {
//            input.parse::<u64>()
//                .map(|_| ())
//                .map_err(|err| err.to_string())
//        })
//}
//
//pub fn nonce<'a, 'b>() -> Arg<'a, 'b> {
//    Arg::with_name("nonce")
//        .long("nonce")
//        .takes_value(true)
//        .validator(|input| {
//            input.parse::<u64>()
//                .map(|_| ())
//                .map_err(|err| err.to_string())
//        })
//}

pub fn capacity<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("capacity")
        .long("capacity")
        .takes_value(true)
        .validator(|input| CapacityParser.validate(input))
        .help("The capacity (unit: CKB, format: 123.335)")
}

pub fn tx_fee<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("tx-fee")
        .long("tx-fee")
        .takes_value(true)
        .validator(|input| CapacityParser.validate(input))
        .help("The transaction fee capacity (unit: CKB, format: 0.0001)")
}

pub fn type_hash<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("type-hash")
        .long("type-hash")
        .takes_value(true)
        .validator(|input| FixedHashParser::<H256>::default().validate(input))
        .help("The type script hash")
}

pub fn amount_hash<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("amount-hash")
        .long("amount-hash")
        .takes_value(true)
        .validator(|input| FixedHashParser::<H256>::default().validate(input))
        .help("The amount hash, Hash(amount + nonce)")
}

pub fn code_hash<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("code-hash")
        .long("code-hash")
        .takes_value(true)
        .validator(|input| FixedHashParser::<H256>::default().validate(input))
        .help("The type script's code hash")
}

pub fn ft_code_hash<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("ft-code-hash")
        .long("ft-code-hash")
        .takes_value(true)
        .validator(|input| FixedHashParser::<H256>::default().validate(input))
        .help("The FT type script's code hash")
}

pub fn live_cells_limit<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("limit")
        .long("limit")
        .takes_value(true)
        .validator(|input| FromStrParser::<usize>::default().validate(input))
        .default_value("15")
        .help("Get live cells <= limit")
}

pub fn from_block_number<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("from")
        .long("from")
        .takes_value(true)
        .validator(|input| FromStrParser::<u64>::default().validate(input))
        .help("From block number (inclusive)")
}

pub fn to_block_number<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("to")
        .long("to")
        .takes_value(true)
        .validator(|input| FromStrParser::<u64>::default().validate(input))
        .help("To block number (inclusive)")
}

pub fn top_n<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("number")
        .short("n")
        .long("number")
        .takes_value(true)
        .validator(|input| FromStrParser::<u32>::default().validate(input))
        .default_value("10")
        .help("Get top n capacity addresses")
}

pub fn out_point<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("out-point")
        .long("out-point")
        .takes_value(true)
        .validator(|input| { OutPointParser.validate(input) })
        .help("out-point to specify a cell. Example: 0xd56ed5d4e8984701714de9744a533413f79604b3b91461e2265614829d2005d1-1")
}

pub fn ft_out_point<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("ft-out-point")
        .long("ft-out-point")
        .takes_value(true)
        .validator(|input| { OutPointParser.validate(input) })
        .help("out-point points to FT binary cell. Example: 0xd56ed5d4e8984701714de9744a533413f79604b3b91461e2265614829d2005d1-1")
}
