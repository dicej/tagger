#[derive(Debug, Eq, PartialEq)]
pub enum TagExpression {
    Or(Box<TagExpression>, Box<TagExpression>),
    And(Box<TagExpression>, Box<TagExpression>),
    Tag(String),
}

impl TagExpression {
    pub fn to_sql_string(&self) -> String {
        match self {
            TagExpression::Or(a, b) => format!("({} OR {})", a.to_sql_string(), b.to_sql_string()),
            TagExpression::And(a, b) => format!("({} AND {})", a.to_sql_string(), b.to_sql_string()),
            TagExpression::Tag(s) => s.to_owned(),
        }
    }

    pub fn fold_tags<'a, T>(&'a self, value: T, fold: impl Fn(T, &'a str) -> T + Copy) -> T {
        match self {
            TagExpression::Or(a, b) | TagExpression::And(a, b) => b.fold_tags(a.fold_tags(value, fold), fold),
            TagExpression::Tag(s) => fold(value, s),
        }
    }
}
