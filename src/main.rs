use std::str::FromStr;

use bip32::{DerivationPath, XPrv};
use bip32::secp256k1::ecdsa::SigningKey;
use bip39::{Language, Mnemonic, Seed};
use hex::{self, ToHex};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use tiny_keccak::{Hasher, Keccak};

fn main() {
    let mnemonic = "";
    let mnemonic2 = use_xor_mnemonic_to_generate_new_mnemonic(mnemonic, "");
    println!("Titan-> {}", mnemonic2);
    let mnemonic3 = use_xor_mnemonic_to_generate_new_mnemonic(&mnemonic2, "");
    println!("第二次异或助记词：{}", mnemonic3);

}

//up
fn use_xor_mnemonic_to_recover_private_key_orin(mnemonic : &str, xor: &str ) -> String {

    let entropy = mnemonic_phrase_to_entropy(mnemonic);
    let xor = xor_entropy_to_private_key(&entropy, xor);
    let private_key_orin = xor.to_bytes();

    private_key_orin.encode_hex::<String>()

}

//down
/// 将原有私钥异或后 当做下一个助记词的熵
/// 以便产生新的助记词
fn use_xor_mnemonic_to_generate_new_mnemonic(mnemonic : &str, xor: &str ) -> String {
    // 从助记词生成私钥
    let private_key = mnemonic_phrase_to_private_key(mnemonic);

    //异或私钥生成熵
    let xor = xor_private_key_to_entropy(&private_key, xor);

    //熵到助记词
    let mnemonic2 = entropy_to_mnemonic_phrase(&xor);
    // println!("异或助记词：{}", mnemonic2);

    mnemonic2
}

/// 助记词推导私钥
fn mnemonic_phrase_to_private_key(mnemonic_phrase: &str) -> SigningKey {
    // 从助记词创建助记词实例
    let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English).expect("创建助记词失败");

    // 从助记词生成种子
    let seed = Seed::new(&mnemonic, "");

    // 从种子生成扩展私钥
    let xprv = XPrv::new(seed.as_bytes()).expect("创建扩展私钥失败");

    // 定义派生路径 bip44 以太坊派生空间 "m/44'/60'/0'/0/0"
    let derivation_path = DerivationPath::from_str("m/44'/60'/0'/0/0").expect("非法派生路径");

    // 逐个处理派生路径中的每个 ChildNumber
    let mut derived_xprv = xprv;
    for child_number in derivation_path {
        derived_xprv = derived_xprv.derive_child(child_number).expect("派生私钥失败");
    }

    // 获取派生私钥
    let private_key = derived_xprv.private_key();

    // 使用椭圆曲线算法从私钥生成公钥
    let secp = Secp256k1::new();

    let secret_key = SecretKey::from_slice(&*private_key.to_bytes()).expect("无效私钥");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    // 对公钥进行Keccak-256哈希计算
    let mut hasher = Keccak::v256();
    let mut hash_output = [0u8; 32];
    hasher.update(&public_key.serialize_uncompressed()[1..]); // 使用未压缩的公钥，不包括前缀
    hasher.finalize(&mut hash_output);

    // 从哈希值中提取以太坊地址（取最后20个字节）
    let address = &hash_output[12..];

    // 将地址转换为十六进制字符串形式
    let hex_address = address.encode_hex::<String>();
    let eth_address = format!("0x{}", hex_address);

    // 打印以太坊地址
    println!("助记词以太坊地址: {}", eth_address);
    // 打印私钥（以十六进制字符串形式）
    // println!("私钥: {}", private_key.clone().to_bytes().encode_hex::<String>());
    private_key.clone()
}

/// 异或私钥到助记词熵
fn xor_private_key_to_entropy(private_key_bytes: &SigningKey, str: &str) -> Vec<u8> {
    // XOR 私钥 异或
    let bytes = str.as_bytes();
    let repeated_bytes: Vec<u8> = bytes.iter()
        .cycle()
        .take(private_key_bytes.to_bytes().len())
        .cloned()
        .collect();

    // 私钥的转为bytes做异或运算
    let xor_bytes: Vec<u8> = private_key_bytes
        .to_bytes()
        .iter()
        .zip(repeated_bytes.iter())
        .map(|(&a, &b)| a ^ b)
        .collect();

    xor_bytes
}

/// 异或熵到私钥
fn xor_entropy_to_private_key(entropy_bytes: &Vec<u8>, str: &str) -> SigningKey {

    let bytes = str.as_bytes();
    let repeated_bytes: Vec<u8> = bytes.iter()
        .cycle()
        .take(entropy_bytes.len())
        .cloned()
        .collect();

    // xor entropy_bytes
    let xor_bytes = entropy_bytes
        .iter()
        .zip(repeated_bytes.iter())
        .map(|(&a, &b)| a ^ b)
        .collect();

    let private_key = SigningKey::from_bytes(&xor_bytes).expect("无效私钥");
    private_key

}

/// 使用新的熵创建助记词
fn entropy_to_mnemonic_phrase(entropy_bytes: &Vec<u8>) -> String {
    // 从助记词创建助记词实例
    let mnemonic = Mnemonic::from_entropy(entropy_bytes, Language::English).expect("创建助记词失败");

    mnemonic.phrase().to_string()
}

/// 助记词转换到熵
fn mnemonic_phrase_to_entropy(mnemonic_phrase: &str) -> Vec<u8> {
    let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English).expect("创建助记词失败");
    let entropy = mnemonic.entropy();

    entropy.to_vec() // Clone the data to return an owned Vec<u8>
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all() {
        let mnemonic = "poet govern brand hockey family must mutual talent distance possible beauty cube";
        // 从助记词生成私钥
        let private_key = mnemonic_phrase_to_private_key(mnemonic);
        println!("钱包私钥： {}", private_key.to_bytes().encode_hex::<String>());

        println!("_________________________________________________________________");
        //异或私钥生成熵
        let xor = xor_private_key_to_entropy(&private_key, "xxx");
        println!("第一次异或熵：{}", xor.encode_hex::<String>());

        //熵到助记词
        let mnemonic2 = entropy_to_mnemonic_phrase(&xor);
        println!("第一次异或助记词：{}", mnemonic2);

        // 助记词转化熵
        let xor_orin = mnemonic_phrase_to_entropy(&*mnemonic2);
        println!("第一次助记词到熵：{}", xor_orin.encode_hex::<String>());
        assert_eq!(xor,xor_orin ,"异或熵还原失败");

        // mnemonic2 to private key
        let private_key2 = mnemonic_phrase_to_private_key(&mnemonic2);
        println!("钛版私钥： {}", private_key2.to_bytes().encode_hex::<String>());

        let private_key_orin = xor_entropy_to_private_key(&xor_orin, "xxx");
        println!("第一次异或还原私钥：{}", private_key_orin.to_bytes().encode_hex::<String>());

        assert_eq!(private_key_orin, private_key ,"xor 还原失败");

        println!("_________________________________________________________________");
        let xor2 = xor_private_key_to_entropy(&private_key2, "xxxx");
        println!("第二次异或熵：{}", xor2.encode_hex::<String>());

        let mnemonic3 = entropy_to_mnemonic_phrase(&xor2);
        println!("第二次异或助记词：{}", mnemonic3);

        let xor3 = mnemonic_phrase_to_entropy(&*mnemonic3);
        println!("第二次助记词到熵：{}", xor3.encode_hex::<String>());
        println!("______________________________test end___________________________________\n");
    }


    #[test]
    fn test_use_oxr_mnemonic_to_generate_new_mnemonic() {
        let mnemonic = "poet govern brand hockey family must mutual talent distance possible beauty cube";
        let mnemonic2 = use_xor_mnemonic_to_generate_new_mnemonic(mnemonic, "xxx");
        println!("第一次异或助记词：{}", mnemonic2);
        let mnemonic3 = use_xor_mnemonic_to_generate_new_mnemonic(&mnemonic2, "xxxx");
        println!("第二次异或助记词：{}", mnemonic3);
        println!("_______________________________test end__________________________________\n");

    }

    #[test]
    fn test_use_xor_mnemonic_to_recover_private_key_orin() {
        let mnemonic3 = "army supply earn mango ball amateur spin display they erosion cable draft shrug gospel swing chief color wing lend end subject gossip bid chest";
        let private_key_orin2 = use_xor_mnemonic_to_recover_private_key_orin(mnemonic3, "xxxx");
        println!("第一次异或后私钥 {}", private_key_orin2);

        let mnemonice2 = "enlist direct unaware maximum dragon mesh retire confirm ladder egg wine border plastic slow antenna final battle dune oven moon trap fatigue rigid faint";
        let private_key_orin=  use_xor_mnemonic_to_recover_private_key_orin(mnemonice2, "xxx");
        println!("钱包私钥 {}", private_key_orin);
        println!("______________________________test end___________________________________\n");
    }
}