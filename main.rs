use tfhe::prelude::*; 
use tfhe::{generate_keys, ConfigBuilder, set_server_key, ClientKey};
use tfhe::{FheInt8, FheInt32, FheBool};
use std::time::Instant;
use std::collections::HashSet;

#[derive(Clone)]
pub struct Node{
    pub state: Vec<FheInt8>,
    pub g: FheInt8,
    pub h: FheInt8,
    pub f: FheInt8,
    pub current_idx: i32,
    pub parent_idx: i32,

    pub zero: FheInt8,
    pub one: FheInt8,
}

impl Node{
    pub fn new(state: Vec<FheInt8>, g: FheInt8, current_idx: i32, parent_idx: i32, zero: FheInt8, one: FheInt8) -> Self{
        Node {
            state: state,
            g: g,
            h: zero.clone(),
            f: zero.clone(),
            current_idx: current_idx,
            parent_idx: parent_idx,

            zero: zero.clone(),
            one: one,
        }
    }

    pub fn heuristic(&mut self, t: &Vec<FheInt8>) {
        let mut total_h = self.zero.clone();

        for (current_val, target_val) in self.state.iter().zip(t.iter()) {
            let is_correct: FheBool = (current_val - target_val).eq(&self.zero);
            let cost = is_correct.select(&self.zero, &self.one);
            
            total_h = &total_h + &cost;
        }

        self.h = total_h;
        self.f = &self.g + &self.h;
    }

    pub fn get_state(&self) -> Vec<FheInt8> {
        self.state.clone()
    }

    pub fn get_f(&self) -> FheInt8 {
        self.f.clone()
    }

    pub fn get_h(&self) -> FheInt8 {
        self.h.clone()
    }

    pub fn set_parent(&mut self, idx: i32) {
        self.parent_idx = idx;
    }
}

pub struct List{
    pub open: Vec<Node>,
    pub open_idx: Vec<i32>,
    pub close: Vec<Node>,
    pub close_idx: Vec<i32>,
} 

impl List{
    pub fn new() -> Self{
        List {
            open: Vec::new(),
            open_idx: Vec::new(),
            close: Vec::new(),
            close_idx: Vec::new(),
        }
    }
    
    pub fn push_open(&mut self, node: &Node){
        self.open_idx.push(node.current_idx);
        self.open.push(node.clone());
    }

    pub fn get_list_size(&self) -> i32{
        (self.open_idx.len() + self.close_idx.len())as i32
    }

    pub fn get_open(&self) -> &Vec<Node>{
        &self.open
    }

    pub fn get_from_idx(&self, index: i32) -> Node {
        if let Some(node) = self.open.iter().find(|n| n.current_idx == index) {
            return node.clone();
        }

        if let Some(node) = self.close.iter().find(|n| n.current_idx == index) {
            return node.clone();
        }
        
        panic!("Critical Error: Node index {} not found anywhere!", index);
    }

    pub fn mv_open_to_close(&mut self, node: &Node){
        if let Some(index) = self.open_idx.iter().position(|&idx| idx == node.current_idx){
            self.open.swap_remove(index);
            self.open_idx.swap_remove(index);
            self.push_close(node);
        }
    }

    pub fn push_close(&mut self, node: &Node){
        self.close_idx.push(node.current_idx);
        self.close.push(node.clone());
    }

    pub fn get_close(&self) -> Vec<Node>{
        self.close.clone()
    }
}

fn main() {
    // Setting and Key generate
    println!("Generating keys... (This might take a while)");
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    // Server Key generate
    set_server_key(server_key);

    // Set start state, destination state
    let start_point: Vec<i8> = vec![2, 4, 3, 7, 0, 5, 1, 6, 1];
    // let desti_point: Vec<i8> = vec![1, 2, 3, 0, 4, 6, 5, 7, 1];
    let desti_point: Vec<i8> = vec![1, 2, 3, 4, 0, 5, 6, 7, 1];

    // Initial value encryption
    let enc_zero =  FheInt8::try_encrypt_trivial(0).unwrap();
    let enc_one = FheInt8::try_encrypt_trivial(1).unwrap();
    let enc_spoint = enc_vec(&start_point, &client_key);
    let enc_dpoint = enc_vec(&desti_point, &client_key);

    // measument start
    let start_time = Instant::now();

    let mut list = List::new();
    let mut curr_node = Node::new(enc_spoint, enc_zero.clone(), 1, -1, enc_zero.clone(), enc_one.clone());
    curr_node.heuristic(&enc_dpoint);
    list.push_open(&curr_node);

    // closed list on Client
    let mut clist:HashSet<Vec<i8>> = HashSet::new();
    let mut pass_sign: bool;
   
    let terminate = false;
    let mut loop_count = 0;

    while !terminate {
        // get minimum cost index
        let enc_min_idx = compare_cost(list.get_open());
        
        // ----------------------- //
        // Client helpe sector
        // encrypted minimum cost decrypt
        let min_idx: i32 = FheInt32::decrypt(&enc_min_idx, &client_key);
        // ----------------------- //

        // get node of minimum index
        curr_node = list.get_from_idx(min_idx);

        // ----------------------- //
        // Client helpe sector
        // algorithm terminate check
        let enc_state = curr_node.get_state();
        let dec_state = dec_vec(&enc_state, &client_key);

        if !clist.insert(dec_state.clone()) {
            pass_sign = true;
        } else {
            pass_sign = false;
        }

        let enc_h = curr_node.get_h();
        let dec_h: i8 = FheInt8::decrypt(&enc_h, &client_key);

        if dec_h == 0 {
            break;
        }
        // ----------------------- //

        // node to close list
        list.mv_open_to_close(&curr_node);

        if !pass_sign {
            // Gamma operation
            let childnode_set = gamma_operation(&curr_node, list.get_list_size()+1, &enc_dpoint);

            for childnode in childnode_set {
                list.push_open(&childnode);
            }

            loop_count += 1;
            if loop_count % 1 == 0 {
                let elapsed = start_time.elapsed();
                println!(
                    "🔄 [Loop {}] running time: {:.2}s (avg {:.4}s/cycle)", 
                    loop_count, 
                    elapsed.as_secs_f64(),
                    elapsed.as_secs_f64() / loop_count as f64
                );

                let f_value:i8 = FheInt8::decrypt(&curr_node.get_f(), &client_key);
                let h_value:i8 = FheInt8::decrypt(&curr_node.get_h(), &client_key);

                println!(
                    "✅ f and h value: {}, {}",
                    f_value,
                    h_value,
                );
            }
        }
    }

    let mut enc_optimal_path: Vec<Node> = Vec::new();
    let steps = false;
    
    while !steps{
        enc_optimal_path.push(curr_node.clone());

        if curr_node.current_idx == 1{
            break;
        }
        
        curr_node = list.get_from_idx(curr_node.parent_idx);
    }
    
    let mut optimal_path: Vec<Vec<i8>> = Vec::new();

    for node in enc_optimal_path{
        optimal_path.push(dec_vec(&node.state, &client_key));
    }
    optimal_path.reverse();

    // end algorithm
    let duration = start_time.elapsed();

    println!("running time : {}s", duration.as_secs_f64());

    for (i, state) in optimal_path.iter().enumerate(){
        println!("{}, {:?}", i, state);
    }
    
}

fn enc_vec(x: &Vec<i8>, key: &ClientKey) -> Vec<FheInt8>{
    x.iter()
        .map(|val| FheInt8::encrypt(*val, key))
        .collect()
}

fn dec_vec(enc_x: &Vec<FheInt8>, key: &ClientKey) ->Vec<i8>{
    enc_x.iter()
        .map(|val| FheInt8::decrypt(val, key))
        .collect()
}

fn compare_cost(node_set: &Vec<Node>) -> FheInt32{
    let mut min_f = node_set[0].get_f();
    let mut min_idx = FheInt32::try_encrypt_trivial(node_set[0].current_idx).unwrap();

    for node in node_set.iter().skip(1) {
        let is_smaller: FheBool = node.get_f().lt(&min_f);

        min_f = is_smaller.select(&node.get_f(), &min_f);

        let curr_idx_enc = FheInt32::try_encrypt_trivial(node.current_idx).unwrap();
        min_idx = is_smaller.select(&curr_idx_enc, &min_idx);
    }

    min_idx
}

fn gamma_operation(parent: &Node, next_idx_start: i32, desti: &Vec<FheInt8>) ->Vec<Node> {
    let mut children: Vec<Node> = Vec::new();
    let mut current_idx_counter = next_idx_start;

    // four forward define
    // Up(-3), Down(+3), Left(-1), Right(+1)
    let directions = [(-3, "Up"), (3, "Down"), (-1, "Left"), (1, "Right")];

    // compare with blank(0)
    let zero_enc = FheInt8::try_encrypt_trivial(0).unwrap();
    // increasement g
    let one_cost = FheInt8::try_encrypt_trivial(1).unwrap();

    for (offset, _dir_name) in directions.iter() {
        // 1. parent state clone
        let mut new_state = parent.state.clone();
        
        // 2. valid swap check 3x3 puzzle based (0~8 인덱스)
        for i in 0..9 {
            let target = i as i8 + offset;

            // out of bound check
            if target < 0 || target >= 9 { continue; }

            // (2) boundary check (protect Left/Right line swap)
            if *offset == 1 && (i % 3 == 2) { continue; } // Right wall
            if *offset == -1 && (i % 3 == 0) { continue; } // Left wall

            let target = target as usize;

            // (3) swap logic (Blind Swap)
            let is_zero: FheBool = parent.state[i].eq(&zero_enc);

            // if value is 0 swap, else keep (use select)
            let val_i = new_state[i].clone();       // present value (probabliy 0)
            let val_target = new_state[target].clone(); // chage target value

            // i position: if 0 is current, get target, else keep
            new_state[i] = is_zero.select(&val_target, &val_i);
            
            // target position: if i is 0, bring 0(val_i), else keep
            new_state[target] = is_zero.select(&val_i, &val_target);
        }

        // 3. calculation g(n) : parent g + 1
        let new_g = &parent.g + &one_cost;

        let zero = FheInt8::try_encrypt_trivial(0).unwrap();
        let one = FheInt8::try_encrypt_trivial(1).unwrap();

        // 4. gen new node
        let mut child_node = Node::new(
            new_state,
            new_g,
            current_idx_counter,
            parent.current_idx,

            zero,
            one,
        );

        child_node.heuristic(&desti);

        children.push(child_node);
        current_idx_counter += 1;
    }

    children
}