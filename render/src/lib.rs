#![deny(warnings)]

#[macro_use]
pub mod macros;
pub mod render;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
