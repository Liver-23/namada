//! Helpers for use in multitoken tests.
use std::path::PathBuf;
use std::str::FromStr;

use borsh::BorshSerialize;
use color_eyre::eyre::Result;
use eyre::Context;
use namada_core::types::address::Address;
use namada_core::types::{storage, token};
use namada_test_utils::tx_data::TxWriteData;
use namada_tx_prelude::storage::KeySeg;
use rand::Rng;
use regex::Regex;

use super::setup::constants::{wasm_abs_path, NAM, VP_ALWAYS_TRUE_WASM};
use super::setup::{Bin, NamadaCmd, Test};
use crate::e2e::setup::constants::{ALBERT, TX_WRITE_WASM};
use crate::run;

const MULTITOKEN_KEY_SEGMENT: &str = "tokens";
const BALANCE_KEY_SEGMENT: &str = "balance";
const RED_TOKEN_KEY_SEGMENT: &str = "red";
const MULTITOKEN_RED_TOKEN_SUB_PREFIX: &str = "tokens/red";

const ARBITRARY_SIGNER: &str = ALBERT;

/// Initializes a VP to represent a multitoken account.
pub fn init_multitoken_vp(test: &Test, rpc_addr: &str) -> Result<String> {
    // we use a VP that always returns true for the multitoken VP here, as we
    // are testing out the VPs of the sender and receiver of multitoken
    // transactions here - not any multitoken VP itself
    let multitoken_vp_wasm_path = wasm_abs_path(VP_ALWAYS_TRUE_WASM)
        .to_string_lossy()
        .to_string();
    let multitoken_alias = "multitoken";

    let init_account_args = vec![
        "init-account",
        "--source",
        ARBITRARY_SIGNER,
        "--public-key",
        // Value obtained from
        // `namada::types::key::ed25519::tests::gen_keypair`
        "001be519a321e29020fa3cbfbfd01bd5e92db134305609270b71dace25b5a21168",
        "--code-path",
        &multitoken_vp_wasm_path,
        "--alias",
        multitoken_alias,
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--ledger-address",
        rpc_addr,
    ];
    let mut client_init_account =
        run!(test, Bin::Client, init_account_args, Some(40))?;
    client_init_account.exp_string("Transaction is valid.")?;
    client_init_account.exp_string("Transaction applied")?;
    client_init_account.assert_success();
    Ok(multitoken_alias.to_string())
}

/// Generates a random path within the `test` directory.
fn generate_random_test_dir_path(test: &Test) -> PathBuf {
    let rng = rand::thread_rng();
    let random_string: String = rng
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(24)
        .map(char::from)
        .collect();
    test.test_dir.path().join(random_string)
}

/// Writes `contents` to a random path within the `test` directory, and return
/// the path.
pub fn write_test_file(
    test: &Test,
    contents: impl AsRef<[u8]>,
) -> Result<PathBuf> {
    let path = generate_random_test_dir_path(test);
    std::fs::write(&path, contents)?;
    Ok(path)
}

/// Mint red tokens to the given address.
pub fn mint_red_tokens(
    test: &Test,
    rpc_addr: &str,
    multitoken: &Address,
    owner: &Address,
    amount: &token::Amount,
) -> Result<()> {
    let red_balance_key = storage::Key::from(multitoken.to_db_key())
        .push(&MULTITOKEN_KEY_SEGMENT.to_owned())?
        .push(&RED_TOKEN_KEY_SEGMENT.to_owned())?
        .push(&BALANCE_KEY_SEGMENT.to_owned())?
        .push(owner)?;

    let tx_code_path = wasm_abs_path(TX_WRITE_WASM);
    let tx_data_path = write_test_file(
        test,
        TxWriteData {
            key: red_balance_key,
            value: amount.try_to_vec()?,
        }
        .try_to_vec()?,
    )?;

    let tx_data_path = tx_data_path.to_string_lossy().to_string();
    let tx_code_path = tx_code_path.to_string_lossy().to_string();
    let tx_args = vec![
        "tx",
        "--signer",
        ARBITRARY_SIGNER,
        "--code-path",
        &tx_code_path,
        "--data-path",
        &tx_data_path,
        "--ledger-address",
        rpc_addr,
    ];
    let mut client_tx = run!(test, Bin::Client, tx_args, Some(40))?;
    client_tx.exp_string("Transaction is valid.")?;
    client_tx.exp_string("Transaction applied")?;
    client_tx.assert_success();
    Ok(())
}

pub fn attempt_red_tokens_transfer(
    test: &Test,
    rpc_addr: &str,
    multitoken: &str,
    from: &str,
    to: &str,
    signer: &str,
    amount: &token::Amount,
) -> Result<NamadaCmd> {
    let amount = amount.to_string();
    let transfer_args = vec![
        "transfer",
        "--token",
        multitoken,
        "--sub-prefix",
        MULTITOKEN_RED_TOKEN_SUB_PREFIX,
        "--source",
        from,
        "--target",
        to,
        "--signer",
        signer,
        "--amount",
        &amount,
        "--ledger-address",
        rpc_addr,
    ];
    run!(test, Bin::Client, transfer_args, Some(40))
}

pub fn fetch_red_token_balance(
    test: &Test,
    rpc_addr: &str,
    multitoken_alias: &str,
    owner_alias: &str,
) -> Result<token::Amount> {
    let balance_args = vec![
        "balance",
        "--owner",
        owner_alias,
        "--token",
        multitoken_alias,
        "--sub-prefix",
        MULTITOKEN_RED_TOKEN_SUB_PREFIX,
        "--ledger-address",
        rpc_addr,
    ];
    let mut client_balance = run!(test, Bin::Client, balance_args, Some(40))?;
    let (_, matched) = client_balance.exp_regex(&format!(
        r"{MULTITOKEN_RED_TOKEN_SUB_PREFIX}: (\d*\.?\d+)"
    ))?;
    let decimal_regex = Regex::new(r"(\d*\.?\d+)").unwrap();
    println!("Got balance for {}: {}", owner_alias, matched);
    let decimal = decimal_regex.find(&matched).unwrap().as_str();
    client_balance.assert_success();
    token::Amount::from_str(decimal)
        .wrap_err(format!("Failed to parse {}", matched))
}
