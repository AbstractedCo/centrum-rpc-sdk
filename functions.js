import {
  ethers,
  parseEther,
  keccak256,
  Transaction,
} from "https://esm.sh/ethers@latest";

import { web3FromSource } from "https://esm.sh/@polkadot/extension-dapp@latest";

import bitcoin from "https://esm.sh/bitcoinjs-lib@latest";

export async function buildTx(from, to, value) {
  const provider = new ethers.JsonRpcProvider(
    "https://ethereum-sepolia-rpc.publicnode.com"
  );

  const transactionObject = {
    to,
    value: parseEther(value),
  };

  const unsignedTx = Transaction.from(transactionObject).unsignedSerialized;

  const unsignedTxHash = keccak256(unsignedTx);

  return unsignedTxHash;
}

export async function signPayloadPls(source, payload) {
  const injector = await web3FromSource(source);

  const signer = injector.signer;

  const { signature } = await signer.signPayload(payload);

  return signature;
}

async function fetchUTXOs(address) {
  try {
    const response = await fetch(
      `https://blockstream.info/testnet/api/address/${address}/utxo`
    );
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error("Error fetching UTXOs:", error);
    return [];
  }
}

export async function buildUnsignedTransaction(from, to, amount) {
  // try {
  //const utxos = await fetchUTXOs(from);

  // const psbt = new bitcoin.Psbt({ network: bitcoin.networks.testnet });

  //console.log("Fetched UTXOs:", utxos);

  // utxos.forEach((utxo) => {
  //   try {
  //     const hashBytes = hexToUint8Array(utxo.txid).reverse();

  //     psbt.addInput({
  //       hash: utxo.txid,
  //       index: utxo.vout,
  //       value: parseInt(utxo.value),
  //     });
  //   } catch (error) {
  //     console.error("Error adding input:", error);
  //   }
  // });

  // console.log("amount: ", amount);

  // psbt.addOutput({
  //   address: to,
  //   value: parseInt(amount),
  // });

  // psbt.finalizeAllInputs();

  // const unsignedTx = psbt.extractTransaction();

  //  return unsignedTx;
  // } catch (error) {
  //   console.error("Error building transaction:", error);
  // }

  const tx = await createTransaction(from, to, parseInt(amount));

  return tx;
}

export function hashFromUnsignedTx(unsignedTx) {
  return unsignedTx.tosign[0];
}

// export async function getBitcoinBalance(address) {
//   try {
//     const response = await fetch(
//       `https://blockstream.info/testnet/api/address/${address}/utxo`
//     );

//     if (!response.ok) {
//       throw new Error(`HTTP error! Status: ${response.status}`);
//     }

//     const utxos = await response.json();

//     // Calculate total balance from UTXOs
//     let totalBalance = 0;
//     utxos.forEach((utxo) => {
//       totalBalance += utxo.value;
//     });

//     console.log(
//       `Bitcoin address ${address} balance: ${totalBalance / 1e8} BTC`
//     );
//     return totalBalance / 1e8; // Convert satoshis to BTC
//   } catch (error) {
//     console.error("Error fetching balance:", error);
//     return 0;
//   }
// }

export async function getBitcoinBalance(address) {
  try {
    const response = await fetch(
      `https://api.blockcypher.com/v1/bcy/test/addrs/${address}/balance`
    );

    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }

    const data = await response.json();

    const balance = data.balance;

    console.log(`Bitcoin address ${address} balance: ${balance / 1e8} BTC`);
    return balance / 1e8; // Convert satoshis to BTC
  } catch (error) {
    console.error("Error fetching balance:", error);
    return 0;
  }
}

async function createTransaction(from, to, amount) {
  try {
    const url = "https://api.blockcypher.com/v1/bcy/test/txs/new";
    const requestBody = {
      inputs: [
        {
          addresses: [from],
        },
      ],
      outputs: [
        {
          addresses: [to],
          value: amount, // amount in satoshis
        },
      ],
    };

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      throw new Error("Failed to create transaction");
    }

    const responseData = await response.json();

    return responseData;
  } catch (error) {
    console.error("Error creating transaction:", error);
  }
}

async function submitTransaction(tx) {
  try {
    const url =
      "https://api.blockcypher.com/v1/bcy/test/txs/send?token=4533e4978e304937a5d224f48cbe23a0"; // Testnet endpoint
    const requestBody = tx;

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      throw new Error("Failed to create transaction");
    }

    const responseData = await response.json();

    return responseData;
  } catch (error) {
    console.error("Error creating transaction:", error);
  }
}

export async function fillTxAndSubmit(unsignedTx, signature, pubkey) {
  let tx = unsignedTx;

  tx.signatures = [signature];
  tx.pubkeys = [pubkey];

  const res = await submitTransaction(tx);

  console.log(res);

  return res.tx.hash;
}
