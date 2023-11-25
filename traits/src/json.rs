use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::PathBuf,
};

use serde::{de::DeserializeOwned, Serialize};

pub trait JsonSync {
    type T: Serialize + DeserializeOwned;

    fn to_file_or_default(this: Option<Self::T>, path: &PathBuf) -> std::io::Result<()> {
        let val = this.unwrap_or(Self::new());
        Self::to_file(&val, path)
    }

    fn to_file(this: &Self::T, path: &PathBuf) -> std::io::Result<()> {
        let opt = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .clone();

        let mut file = opt.open(path)?;
        let str = serde_json::to_string_pretty(&this)?;

        file.write(&str.as_bytes())?;

        Ok(())
    }

    fn from_file(path: &PathBuf) -> std::io::Result<Self::T> {
        let opt = OpenOptions::new().read(true).clone();

        let mut file = opt.open(path)?;
        let mut str = String::new();

        file.read_to_string(&mut str)?;

        let val: Self::T = serde_json::from_str(&str)?;

        Ok(val)
    }

    fn from_file_or_default(path: &PathBuf) -> Self::T {
        Self::from_file(path).unwrap_or(Self::new())
    }

    fn new() -> Self::T;
    fn is_empty(this: &Self::T) -> bool;
}
