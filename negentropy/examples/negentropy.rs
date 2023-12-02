// Copyright (c) 2023 Yuki Kishimoto
// Distributed under the MIT software license

use negentropy::{Bytes, Negentropy};
use negentropy::storage::{NegentropyStorageVector};

fn main() {
    // Client
    let mut storage_client = NegentropyStorageVector::new().unwrap();
    storage_client
        .insert(
            0,
            Bytes::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
        )
        .unwrap();
    storage_client
        .insert(
            1,
            Bytes::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
        )
        .unwrap();
    storage_client.seal().unwrap();
    let mut client = Negentropy::new(&mut storage_client, 9).unwrap();
    let init_output = client.initiate().unwrap();
    println!("Initiator Output: {}", init_output.as_hex());

    // Relay
    let mut storage_relay = NegentropyStorageVector::new().unwrap();
    storage_relay
        .insert(
            0,
            Bytes::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
        )
        .unwrap();
    storage_relay
        .insert(
            2,
            Bytes::from_hex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc").unwrap(),
        )
        .unwrap();
    storage_relay
        .insert(
            3,
            Bytes::from_hex("1111111111111111111111111111111111111111111111111111111111111111").unwrap(),
        )
        .unwrap();
    storage_relay
        .insert(
            5,
            Bytes::from_hex("2222222222222222222222222222222222222222222222222222222222222222").unwrap(),
        )
        .unwrap();
    storage_relay
        .insert(
            10,
            Bytes::from_hex("3333333333333333333333333333333333333333333333333333333333333333").unwrap(),
        )
        .unwrap();
    storage_relay.seal().unwrap();
    let mut relay = Negentropy::new(&mut storage_relay, 0).unwrap();
    let reconcile_output = relay.reconcile(&init_output).unwrap();
    println!("Reconcile Output: {}", reconcile_output.as_hex());

    // Client
    let mut have_ids = Vec::new();
    let mut need_ids = Vec::new();
    let reconcile_output_with_ids = client
        .reconcile_with_ids(&reconcile_output, &mut have_ids, &mut need_ids)
        .unwrap();
    println!(
        "Reconcile Output with IDs: {}",
        reconcile_output_with_ids.unwrap().as_hex()
    );
    println!(
        "Have IDs: {}",
        have_ids
            .into_iter()
            .map(|b| b.to_hex())
            .collect::<Vec<_>>()
            .join("")
    );
    println!(
        "Need IDs: {}",
        need_ids
            .into_iter()
            .map(|b| b.to_hex())
            .collect::<Vec<_>>()
            .join("")
    );
}
