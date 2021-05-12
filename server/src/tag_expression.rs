#[derive(Debug, Eq, PartialEq)]
pub enum TagExpression {
    Or(Box<TagExpression>, Box<TagExpression>),
    And(Box<TagExpression>, Box<TagExpression>),
    Tag(String),
}

impl TagExpression {
    pub fn to_sql_string(&self) -> String {
        fn append(buffer: &mut String, expression: &TagExpression) {
            match expression {
                TagExpression::Or(a, b) => {
                    buffer.push('(');
                    append(buffer, a);
                    buffer.push_str(" OR ");
                    append(buffer, b);
                    buffer.push(')');
                }
                TagExpression::And(a, b) => {
                    buffer.push('(');
                    append(buffer, a);
                    buffer.push_str(" AND ");
                    append(buffer, b);
                    buffer.push(')');
                }
                TagExpression::Tag(_) => buffer.push_str("t.tag = ?"),
            }
        }

        let mut buffer = String::new();
        append(&mut buffer, self);
        buffer
    }

    pub fn fold_tags<'a, T>(&'a self, value: T, fold: impl Fn(T, &'a str) -> T + Copy) -> T {
        match self {
            TagExpression::Or(a, b) | TagExpression::And(a, b) => b.fold_tags(a.fold_tags(value, fold), fold),
            TagExpression::Tag(s) => fold(value, s),
        }
    }
}
