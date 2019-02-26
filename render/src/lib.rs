type Dom = DomTree<DOM>;

struct Element {
    name: &'static str,
    attributes: OrdMap<usize, (&'static str, String)>,
    events: Vec<Event>,
    children: OrdMap<usize, VNode>
}

enum VNode {
    Element(Element),
    Text(String)
}

trait Handler<T> {
    fn handle(t: T) -> VNode
}

struct Listener<T> {
    sublisteners: HashMap<Identity<Render>, Box<SubListener<T>>>,
    handlers: HashMap<Path, Handler>
}

struct Root<T> {
    node: VNode,
    listeners: HashMap<Identity<Render>, Listener<T>>
}

struct PathFinder {
    random: StdRng,
}

impl PathFinder {
    fn make_key(&mut self) -> String {
        iter::repeat(())
            .map(|_| self.random.sample(Alphanumeric))
            .take(8)
            .collect()
    }
}

struct MapState<I, T> {
    inner: Weak<I>,
    sinks: HashSet<Identity<Fn(T)>>
}

struct Map<I, T, F> {
    previous: Option<T>,
    map: F,
    state: Rc<RefCell<MapState<I, T>>>
}

impl <I, T, F: Clone> for Map<I, T, F> {
    fn clone(&self) -> Self {
        Map {
            previous: None,
            map: self.map.clone(),
            state: self.state.clone(),
        }
    }
}

impl <I, T, F> Map<I, T, F> {
    fn map<V, G: Fn(U) -> V + Clone + 'static>(&self, map: G) -> Map<I, Self, G> {
        Map {
            map,
            state: Rc::new(RefCell::new(MapState {
                inner: self.clone().downgrade(),
                contexts: HashMap::new()
            }))
        }
    }

    fn add_use<G: FnOnce() -> Dom, H: FnOnce(VNode) -> UseBody<T>>(&self, root: G, use_body: H) -> String {
        let old_context = self.path_finder.borrow_mut().push_context();
        let root = root();
        let new_context = self.path_finder.borrow_mut().pop_context(old_context.clone());
        let key = new_context.borrow().key.clone();
        let use_ = Rc::new(Use {
            context: new_context,
            body: use_body(resolve(root, &mut new_context.borrow_mut().paths))
        });
        let map = self.clone();
        
        old_context.borrow_mut().on_add.push(Box::new(move || {
            let map = Rc::new(RefCell::new(map.clone()));

            let use_sink = Rc::new({
                let use_ = use_.clone();
                move |state| use_.accept(state)
            });
            
            map.borrow().add_sink(use_sink.clone());
            
            let inner_sink = Rc::new({
                let map = map.clone();
                move |state| map.borrow_mut().accept(state)
            });

            // todo: reduce the number of these to one per MapState
            map.borrow().state.borrow().inner.upgrade().unwrap().add_sink(inner_sink.clone());
            
            Box::new(move || {
                map.borrow().remove_sink(use_sink);
                map.borrow().state.borrow().inner.upgrade().unwrap().remove_sink(inner_sink)
            })
        }));

        key
   }

    fn accept(&mut self, state: T) {
        let mapped = self.map(state);
        if Some(mapped) != self.previous {
            self.previous = Some(mapped.clone());
            for sink in &self.state.borrow().sinks {
                sink(mapped.clone())
            }
        }
    }
}

impl <'a, P, T, U: Eq, F: Fn(T) -> U> Map<'a, P, F> {
    fn case<G: FnOnce() -> Dom>(&self, value: U, root: G) -> String {
        self.map(|state| if state == value {
            Some(value.clone())
        } else {
            None
        }).each(|_| root())
    }
}

impl <'a, P, T, V, W, U: Diff<V, W>, F: Fn(T) -> U + Clone + 'static> Map<'a, P, F> {
    fn each<G: FnOnce(&Render<W>) -> Dom>(&self, root: G) -> String {
        let visitor = Rc::new(Visitor::new());
        
        self.add_use({
            let visitor = visitor.clone();
            move || root(&visitor)
        }, move |root| Use::Each(Each{
            visitor,
            root
        }))
    }
}

struct Value;

struct Each<T> {
    visitor: Rc<Visitor<T>>,
    dom: Dom
}

impl <T> Use<T> {
    fn accept(&self, value: T) {
        match self.body {
            UseBody::Each(each) => {
                for event in self.previous.diff(value) {
                    match event {
                        Add((key, value)) =>
                        // add new subdocument and notify visitor sinks (which should be registered when adding subdocument)
                            ;
                        Remove((key, _)) =>
                        // remove subdocument (which should unregister any associated sinks)
                            ;
                        Update {
                            old: (key, old_value),
                            new: (_, new_value)
                        } =>
                        // notify visitor sinks for specified key
                            ;
                    }
                }
            }
        }
    }
}
