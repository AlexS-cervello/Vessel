use crate::common::{check_token, DB_EXTENSION, VAR_DIR};
use crate::encryption::{copy_pass, create_file, del_pass, upsert_content};
use crate::error::Error;
use clap::{arg, command, ArgAction, Command};
use rpassword;
use std::env;

pub fn run() -> Result<(), Error> {
    let matches = command!()
        .subcommand(
            Command::new("create")
                .about("Creates new database")
                .arg(arg!(-n --name <db_name> "Database name").required(true)),
        )
        .subcommand(
            Command::new("set")
                .about("Add username password pair")
                .arg(arg!(-n --name <db_name> "Database name").required(true))
                .arg(
                    arg!(-u --username <value> "Username")
                        .action(ArgAction::Set)
                        .required(true),
                )
                .arg(
                    arg!(-l --length <value> "Length")
                        .action(ArgAction::Set)
                        .value_parser(clap::value_parser!(u16).range(4..128))
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("get")
                .about("Get password by username")
                .arg(arg!(-n --name <db_name> "Database name").required(true))
                .arg(
                    arg!(-u --username <value> "Username")
                        .action(ArgAction::Set)
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("del")
                .about("Delete password record")
                .arg(arg!(-n --name <db_name> "Database name").required(true))
                .arg(
                    arg!(-u --username <value> "Username")
                        .action(ArgAction::Set)
                        .required(true),
                ),
        )
        .subcommand_required(true)
        .get_matches();
    check_token()?;
    if let Some(matches) = matches.subcommand_matches("create") {
        // Can safely use unwrap as we have required(true)
        let name = matches.get_one::<String>("name").unwrap();
        create_db(name)?;
    }
    if let Some(matches) = matches.subcommand_matches("set") {
        let name = matches.get_one::<String>("name").unwrap();
        let username = matches.get_one::<String>("username").unwrap();
        let length = matches.get_one::<u16>("length").unwrap().to_owned();
        set_pair(&name, &username, length)?;
    }
    if let Some(matches) = matches.subcommand_matches("get") {
        let name = matches.get_one::<String>("name").unwrap();
        let username = matches.get_one::<String>("username").unwrap();
        get_pass(name, username)?;
    }
    if let Some(matches) = matches.subcommand_matches("del") {
        let name = matches.get_one::<String>("name").unwrap();
        let username = matches.get_one::<String>("username").unwrap();
        delete_pass(name, username)?;
    }

    Ok(())
}

fn create_db(name: &String) -> Result<(), Error> {
    let password = rpassword::prompt_password("Enter password for new db: ").unwrap();
    create_file(name, &password)?;

    Ok(())
}

fn set_pair(name: &String, username: &String, length: u16) -> Result<(), Error> {
    let encrypted_file_path = format!("{}{}{}", env::var(VAR_DIR)?, &name, DB_EXTENSION);
    let password = rpassword::prompt_password("Enter password for db: ").unwrap();
    upsert_content(&encrypted_file_path, &password, &username, length)?;

    Ok(())
}

fn get_pass(name: &String, username: &String) -> Result<(), Error> {
    let encrypted_file_path = format!("{}{}{}", env::var(VAR_DIR)?, &name, DB_EXTENSION);
    let password = rpassword::prompt_password("Enter password for db: ").unwrap();
    copy_pass(&encrypted_file_path, username, &password)?;
    Ok(())
}

fn delete_pass(name: &String, username: &String) -> Result<(), Error> {
    let encrypted_file_path = format!("{}{}{}", env::var(VAR_DIR)?, &name, DB_EXTENSION);
    let password = rpassword::prompt_password("Enter password for db: ").unwrap();
    del_pass(&encrypted_file_path, username, &password)?;
    Ok(())
}
