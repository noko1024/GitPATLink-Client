extern crate clap;
extern crate crypto;
extern crate aesstream;
extern crate bcrypt;
extern crate reqwest;
extern crate tokio;
extern crate base64;
extern crate clap_complete;
extern crate uptime_lib;
extern crate rand;

use aesstream::{AesWriter, AesReader};
use crypto::aessafe::{AesSafe256Encryptor, AesSafe256Decryptor};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::io::{Read,Write,Cursor};
use std::process;
use std::io;
use std::env;
use std::fs::File;
use clap_complete::{generate, shells::Bash,shells::Elvish,shells::Fish,shells::PowerShell,shells::Zsh};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::SeedableRng;
use rand::seq::SliceRandom;

mod cli;

#[tokio::main]
async fn main(){
    // 引数を解析
    let matches = cli::build_cli().get_matches();

    // subサブコマンドの解析結果を取得
    if let Some(ref matches) = matches.subcommand_matches("comp"){
        let shell_name = matches.value_of("Shell Name").unwrap().to_string();

        if shell_name == "bash" {
            generate(Bash, &mut cli::build_cli(), "gpad-cli", &mut io::stdout());
        }
        else if shell_name == "zsh" {
            generate(Zsh, &mut cli::build_cli(), "gpad-cli", &mut io::stdout());
        }
        else if shell_name == "powershell" {
            generate(PowerShell, &mut cli::build_cli(), "gpad-cli", &mut io::stdout());
        }
        else if shell_name == "fish" {
            generate(Fish, &mut cli::build_cli(), "gpad-cli", &mut io::stdout());
        }
        else if shell_name == "elvish" {
            generate(Elvish, &mut cli::build_cli(), "gpad-cli", &mut io::stdout());
        }

    }
    else if let Some(ref matches) = matches.subcommand_matches("add") {
        let id = matches.value_of("student ID Number").unwrap().to_string();
        let password = matches.value_of("password").unwrap().to_string();
        let user_name = matches.value_of("user name").unwrap().to_string();
        let token = matches.value_of("Pasonal Access Token").unwrap().to_string();

        /*
        println!("id={}",id);
        println!("password={}",password);
        println!("user_name={}",user_name);
        println!("token={}",token);
        */

        //Pasonal Access Tokenを passwordで暗号化
        let enc_token = _encrypt(&password,token);
        //sha256でpasswordをハッシュ化
        let mut hasher = Sha256::new();
        hasher.input_str(&password.to_string());
        let hash_password = hasher.result_str();


        let user_info = format!("{},{}",user_name,enc_token);

        //println!("{:?}",vec![id.clone(),hash_password.clone(),user_info.clone()]);
        let _res = _http_post("/link/api/add",vec![id,hash_password,user_info]).await;
        //println!("{:?}",res);
        

    }
    else if let Some(ref matches) = matches.subcommand_matches("load") {
        let id = matches.value_of("student ID number").unwrap().to_string();
        let password = matches.value_of("password").unwrap().to_string();

        let mut hasher = Sha256::new();
        hasher.input_str(&password.to_string());
        let hash_password = hasher.result_str();

        let vec_user_info = _http_post("/link/api/get",vec![id,hash_password]).await;
        let user_name = vec_user_info[0].to_string();
        let token = _decrypt(&password, vec_user_info[1].to_string());

        //ファイル保存のため暗号化
        let user_info = user_name+","+&token;
        //println!("{}",user_info);
        let file_enc_password = _gen_password(32,_get_boot_time());
        //println!("{}",file_enc_password);
        let encrypted_user_info = _encrypt(&file_enc_password,user_info);
        //println!("{}",encrypted_user_info);
        let mut save_file_path = env::current_exe().unwrap();
        save_file_path.pop();
        save_file_path.push(".gpadinfo");
        //書き込み準備
        let mut gpad_info_file = match File::create(save_file_path){
            Ok(file) => file,
            Err(_) => {
                println!("File Open Error");
                std::process::exit(1);
            }
        };
        //書き込み
        match gpad_info_file.write_all(encrypted_user_info.as_bytes()){
            Ok(_) => std::process::exit(0),
            Err(_) => {
                    println!("File Write Error");
                    std::process::exit(1)                
            }
        }
    }

    else if let Some(ref matches) = matches.subcommand_matches("remove") {
        let id = matches.value_of("student ID number").unwrap().to_string();
        let password = matches.value_of("password").unwrap().to_string();
        //println!("{}",id);
        //println!("{}",password);
        let mut hasher = Sha256::new();
        hasher.input_str(&password.to_string());
        let hash_password = hasher.result_str();
        let __ = _http_post("/link/api/remove",vec![id,hash_password]).await;
        
    }
    else if let Some(ref __) = matches.subcommand_matches("get"){
        let mut input_user_auth = vec![];
        loop {
            let mut word = String::new();
            std::io::stdin().read_line(&mut word).ok();
            let input_string = word.trim().to_string();
            if input_string == "" {
                break;
            }
            else {
                input_user_auth.push(input_string);
            }
        }
        if input_user_auth.len() <= 1{
            process::exit(1);
        }
        else{
            if !(input_user_auth[0] == "protocol=https" && input_user_auth[1] == "host=github.com"){
                process::exit(0);
            }
        }

        let mut save_file_path = env::current_exe().unwrap();
        save_file_path.pop();
        save_file_path.push(".gpadinfo");
        
        //ファイルからuser_infoを読み込み
        let raw_user_info = match std::fs::read_to_string(save_file_path){
            Ok(data) => data,
            Err(__) => {
                println!("File Read Error");
                std::process::exit(1);
            }
        };
        //password生成
        let file_enc_password = _gen_password(32,_get_boot_time());
        //復号化
        let decrypted_user_info =  _decrypt(&file_enc_password,raw_user_info);
        //csvで保存しているのでVecへデシリアライズ
        let user_info = decrypted_user_info.split(",").collect::<Vec<&str>>();

        println!("protocol=https");
        println!("host=github.com");
        println!("username={}",user_info[0]);
        println!("password={}",user_info[1]);
        
    }
    else if let Some(ref __) = matches.subcommand_matches("store"){
        std::process::exit(0)
    }
    else if let Some(ref __) = matches.subcommand_matches("erase"){
        std::process::exit(0)
    }

fn _get_boot_time() -> u64{
    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let now_uptime = uptime_lib::get().unwrap();
    let boot_time = (now_unix - now_uptime).as_secs();
    return boot_time
}

fn _gen_password(size: usize,seed:u64) -> String {
    const BASE : &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"; 
    let mut rng :rand::rngs::StdRng = SeedableRng::seed_from_u64(seed);

    let passsword = String::from_utf8(
        BASE.as_bytes()
            .choose_multiple(&mut rng , size)
            .cloned()
            .collect()
    ).unwrap();
    return passsword
}

    fn _encrypt(password:&str, source:String) -> String  {
        const PASSWORD_SIZE: usize = 32;
        let key = password.as_bytes(); 
        if key.len()>PASSWORD_SIZE{
            println!("Error:Too long password!");
            process::exit(1);
        }
        let mut key_array = [0u8; PASSWORD_SIZE];               
        for i in 0..key.len() {
            key_array[i] = key[i];
        }
        let encryptor = AesSafe256Encryptor::new(&key_array);
        let mut encrypted = vec![];
        {
            let mut writer = match AesWriter::new(&mut encrypted, encryptor){
                Ok(writer_data) => writer_data,
                Err(__) => {
                    println!("Encrypt Error");
                    std::process::exit(1);
                }
            };
            let _ = writer.write_all(source.as_bytes());
            
        }
        return base64::encode(encrypted);
    }
    

    fn _decrypt(password:&str, source:String)-> String{
        let decoded:Vec<u8> = base64::decode(source).unwrap();
        const PASSWORD_SIZE: usize = 32;
        let key = password.as_bytes(); 
        if key.len()>PASSWORD_SIZE{
            println!("Error:Too long password!");
            process::exit(1);
        }
        let mut key_array = [0u8; PASSWORD_SIZE];               
        for i in 0..key.len() {
            key_array[i] = key[i];
        }
        let decryptor = AesSafe256Decryptor::new(&key_array);
        let mut reader = match AesReader::new(Cursor::new(decoded), decryptor){
            Ok(reader_data) => reader_data,
            Err(__) => {
                println!("Decrypt Error");
                std::process::exit(1);
            }
        };
        let mut decrypted = Vec::new();
        let _ = reader.read_to_end(&mut decrypted);
        let decoded_data = match String::from_utf8(decrypted){
            Ok(data) => data,
            Err(__) => {
                println!("base64 decode Error"); 
                std::process::exit(1);
            }
        };
        return decoded_data;
    }


    async fn _http_post(api_end_point:&str, user_auth_info:Vec<String>) -> Vec<String>{
        let api_root = "http://api.main.noko1024.net".to_string();
        let request_body:String;

        if user_auth_info.len() <= 2{
            request_body = format!("{{\"id\":\"{}\",\"password\":\"{}\"}}", user_auth_info[0],user_auth_info[1]); 
        }
        else{
            request_body = format!("{{\"id\":\"{}\",\"password\":\"{}\",\"userinfo\":\"{}\"}}", user_auth_info[0],user_auth_info[1],user_auth_info[2]);
            //println!("{}",request_body)
        }
        let client = reqwest::Client::new();
        //print!("{}",request_body);
        let response = client.post(api_root+api_end_point)
            .header("Content-Type","application/json")
            .body(request_body)
            .send()
            .await;
            
        let response_data = match response {
            Ok(res) => res,
            Err(_) => {
                println!("NetworkError");
                process::exit(1);
            }
        };

        let status_code = response_data.status().as_u16();
        if status_code == 200{
            let res = response_data.text().await.unwrap();

            let res_text = res.split(",").map(|s| s.to_string()).collect::<Vec<String>>();
            //println!("{}",status_code);
            //println!("{:?}",res_text);
            return res_text;
        }
        else if status_code == 400{
            println!("Error:Internal Client Error");
            println!("Please contact the developer.");
            let res = response_data.text().await;
            let res_text = res.unwrap();
            println!("{}",status_code);
            println!("{}",res_text);
            process::exit(1)
        }
        else if status_code == 401{
            println!("Error:Auth Error");
            println!("Hint:1. Is your password wrong?");
            println!("Hint:2. Possibility that the authentication information has not been registered.");
            let _res = response_data.text().await;
            //let res_text = res.unwrap();
            //println!("{}",status_code);
            //println!("{}",res_text);
            process::exit(1)
        }
        else if status_code == 404{
            println!("Error:Client Adress Error");
            println!("Please contact the developer.");
            let _res = response_data.text().await;
            //let res_text = res.unwrap();
            //println!("{}",status_code);
            //println!("{}",res_text);
            process::exit(1)
        }
        else{
            println!("Error:Internal Server Error. Please try again");
            let _res = response_data.text().await;
            //let res_text = res.unwrap();
            //println!("{}",status_code);
            //println!("{}",res_text);
            process::exit(1)
        }
    }
}
