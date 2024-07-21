
/* DWARF original prototype: void encrypt(&str message, u128 key) */

void __rustcall rust::rust::encrypt(char *message,int key)

{
  undefined value [16];
  &str self;
  Option<u8> OVar1;
  usize capacity;
  ulong in_RCX;
  ulong uVar2;
  byte extraout_DL;
  ulong in_RDX;
  ulong uVar3;
  undefined4 in_register_00000034;
  Bytes self_00;
  &[&str] pieces;
  &str self_01;
  &str expr;
  &str expr_00;
  &[core::fmt::rt::Argument] args;
  Vec<> enc;
  Bytes iter;
  u8 i;
  i128 x;
  i128 shifted;
  i128 xored;
  i128 added;
  i128 cipher;
  u128 key_1;
  Vec<> local_138;
  Iter<u8> local_120;
  undefined local_10a;
  Arguments local_108;
  Argument local_d8;
  Result<> local_c8;
  Stdout local_c0;
  char *local_b8;
  usize local_b0;
  ulong local_80;
  undefined8 local_78;
  ulong local_70;
  undefined8 local_68;
  ulong local_60;
  ulong local_50;
  ulong local_48;
  ulong local_40;
  ulong local_38;
  long local_30;
  long local_28;
  Vec<> *local_20;
  code *local_18;
  Vec<> *local_10;
  code *local_8;
  
  self_01.length = CONCAT44(in_register_00000034,key);
  self_01.data_ptr = (u8 *)message;
  local_b8 = message;
  local_b0 = self_01.length;
  capacity = core::str::len(self_01);
  alloc::vec::Vec<>::with_capacity<i128>(&local_138,capacity);
  self.length = self_01.length;
  self.data_ptr = (u8 *)message;
                    /* try { // try from 0010a1bc to 0010a1c0 has its CatchHandler @ 0010a1e5 */
  self_00 = core::str::bytes(self);
                    /* try { // try from 0010a1fb to 0010a390 has its CatchHandler @ 0010a1e5 */
  local_120 = (Iter<u8>)core::iter::traits::collect::into_iter<>(self_00);
  while( true ) {
    OVar1 = core::str::iter::next((Bytes *)&local_120);
    local_10a = OVar1._0_1_;
    if (((ushort)OVar1 & 1) == 0) {
      local_d8.value = (Opaque *)&local_138;
      local_8 = alloc::vec::fmt<>;
      local_18 = alloc::vec::fmt<>;
      local_d8.formatter = alloc::vec::fmt<>;
      pieces.length = 2;
      pieces.data_ptr = (&str *)&DAT_00162000;
      args.length = 1;
      args.data_ptr = &local_d8;
      local_20 = (Vec<> *)local_d8.value;
      local_10 = (Vec<> *)local_d8.value;
      core::fmt::Arguments::new_v1(&local_108,pieces,args);
      std::io::stdio::_print(&local_108);
      local_c0 = std::io::stdio::stdout();
      local_c8 = std::io::stdio::flush(&local_c0);
      core::ptr::drop_in_place<>(&local_c8);
      core::ptr::drop_in_place<>(&local_138);
      return;
    }
    local_78 = 0;
    local_80 = (ulong)extraout_DL << 5;
    local_70 = local_80 >> 3;
    local_68 = 0;
    local_60 = in_RDX ^ local_70;
    uVar3 = local_60 + 0x539;
    uVar2 = in_RCX + (0xfffffffffffffac6 < local_60);
    if (SCARRY8(in_RCX,0) != SCARRY8(in_RCX,(ulong)(0xfffffffffffffac6 < local_60))) break;
    local_40 = ~uVar3;
    local_38 = ~uVar2;
    local_50 = uVar3;
    local_48 = uVar2;
    if (CARRY8(in_RCX,in_RCX) || CARRY8(in_RCX * 2,(ulong)CARRY8(in_RDX,in_RDX))) {
      expr_00.length = 0x21;
      expr_00.data_ptr = (u8 *)"attempt to multiply with overflow";
                    /* WARNING: Subroutine does not return */
      core::panicking::panic(expr_00);
    }
    value._8_8_ = in_RDX * 2;
    value._0_8_ = local_38;
    local_30 = in_RDX * 2;
    local_28 = in_RCX * 2 + (ulong)CARRY8(in_RDX,in_RDX);
    alloc::vec::Vec<>::push<>(&local_138,(i128)value);
  }
  expr.length = 0x1c;
  expr.data_ptr = (u8 *)"attempt to add with overflow";
                    /* try { // try from 0010a4a0 to 0010a50e has its CatchHandler @ 0010a1e5 */
                    /* WARNING: Subroutine does not return */
  core::panicking::panic(expr);
}

