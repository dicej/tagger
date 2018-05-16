#![deny(warnings)]

#[macro_export]
macro_rules! html_impl {
    ($stack:ident (< $name:ident $($tail:tt)*)) => {
        #[allow(unused_mut)]        
        let mut $stack = ($crate::dispatch::Element::new(stringify!($name)), $stack);
        html_impl! { $stack ($($tail)*) }
    };
    ($stack:ident (onclick = $handler:expr, $($tail:tt)*)) => {
        $stack.0.handlers.push($crate::dispatch::on_click($handler));
        html_impl! { $stack ($($tail)*) }
    };
    ($stack:ident (ondoubleclick = $handler:expr, $($tail:tt)*)) => {
        $stack.0.handlers.push($crate::dispatch::on_double_click($handler));
        html_impl! { $stack ($($tail)*) }
    };
    ($stack:ident ($name:ident = $value:expr, $($tail:tt)*)) => {
        $stack.0.children.push($crate::dispatch::attribute(stringify!($name), $value));
        html_impl! { $stack ($($tail)*) }
    };
    ($stack:ident ({ $value:expr } $($tail:tt)*)) => {
        $stack.0.children.push($crate::dispatch::to_node($value));
        html_impl! { $stack ($($tail)*) }
    };
    ($stack:ident (> $($tail:tt)*)) => {
        html_impl! { $stack ($($tail)*) }
    };
    ($stack:ident (/ > $($tail:tt)*)) => {
        let (car, mut $stack) = $stack;
        $stack.0.children.push(Box::new(car));
        html_impl! { $stack ($($tail)*) }
    };
    ($stack:ident (< / $end:ident > $($tail:tt)*)) => {
        if stringify!($end) != $stack.0.name {
            panic!("mismatched tags: <{}> vs. </{}>", $stack.0.name, stringify!($end));
        }
        let (car, mut $stack) = $stack;
        $stack.0.children.push(Box::new(car));
        html_impl! { $stack ($($tail)*) }
    };
    ($stack:ident ()) => {
        if $stack.0.children.len() != 1 {
            panic!("expected single root element");
        }
        $stack.0.children.pop().unwrap()
    };
}

#[macro_export]
macro_rules! html {
    ($($tail:tt)*) => {{
        #[allow(unused_mut)]
        let mut stack = ($crate::dispatch::Element::new("root"), ());
        html_impl! { stack ($($tail)*) }
    }};
}
