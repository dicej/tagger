#[derive(Debug, Eq, PartialEq)]
pub enum TagExpression {
    Or(Box<TagExpression>, Box<TagExpression>),
    And(Box<TagExpression>, Box<TagExpression>),
    Tag { category: Option<String>, tag: String },
}

impl TagExpression {
    pub fn fold_tags<'a, T>(&'a self, value: T, fold: impl Fn(T, Option<&'a str>, &'a str) -> T + Copy) -> T {
        match self {
            TagExpression::Or(a, b) | TagExpression::And(a, b) => b.fold_tags(a.fold_tags(value, fold), fold),
            TagExpression::Tag { category, tag } => fold(value, category.as_deref(), tag),
        }
    }
}
