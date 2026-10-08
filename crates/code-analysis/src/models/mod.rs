//! Language models: what libraries and frameworks do with data.

pub mod common;
pub mod java;
pub mod python;

use crate::interp::Model;
use crate::Language;

static PYTHON: python::Python = python::Python;
static JAVA: java::Java = java::Java;

/// The library model for code in `lang`.
pub fn for_language(lang: Language) -> &'static dyn Model {
    match lang {
        Language::Python => &PYTHON,
        Language::Java => &JAVA,
        // Not lowered yet: no code in these languages is run.
        Language::Php | Language::C | Language::Cpp => &PYTHON,
    }
}
