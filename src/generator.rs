use random_string::generate;

// In a practice user will need only those 2 dicts
const BASE_DICT: &'static str = "aA1bB2cC3dD4eE5fF6gG7hH8iI9jJ0kKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ";
const EXTENDED_DICT: &'static str =
    "aA1!bB2@cC3#dD4$eE5%fF6^gG7&hH8*iI9(jJ0)kK_lL+mM-nN=oO[pP]qQ{rR}sS;tT:uU>vV<wW?xXyYzZ";

pub enum DictType {
    Base,
    Extended,
}

pub fn generate_string(dict_type: DictType, length: u16) -> String {
    match dict_type {
        DictType::Base => format!("{}", generate(length as usize, BASE_DICT)),
        DictType::Extended => format!("{}", generate(length as usize, EXTENDED_DICT)),
    }
}
