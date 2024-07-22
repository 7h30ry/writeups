from z3 import *

enc = [0x000348a627d10659, 0x27485a840365fe61,
	0x9e735dadf26d31cd, 0x82714bc9f9b579d9,
	0x3dfb7cc801d16bc9, 0x602a04efe5dad659,
	0x0eb801d915a30d3d, 0x217dbe10edcb20a1,
	0xadee2637e875ca19, 0x0cd44aed238e9871,
	0x0d3bff76ae6b504d, 0x7181426eff59e789,
	0x477616cb20c2dac9, 0xce1206e1e46ce4a9,
	0x946e7cb964a3f87d, 0x0499607cbf0c3291,
	0x6871d4372347c759, 0x075412f56b7d8b01,
	0xf8e57c264786e34d, 0x194ca6020ec505b9,
	0x3e1a22e34fe84949, 0xa46de25172742b79,
	0xcd0e971bcbfe6e3d, 0x56561961138a2501,
	0x78d2b538ab53ca19, 0xa9980ca75ab6d611,
	0x5f81576b5d4716cd, 0x17b9860825b93469,
	0xc012f75269298349, 0x17373ee9c7a3aac9,
	0xb2e50798b11e1a7d, 0xada5a6562e0fd7f1,
	0xec3d9a68f1c99e59, 0x3d828b35505d79a1,
	0xf76e5264f7bd16cd, 0xdd230b3ec48ed399,
	0x80d93363dcd354c9, 0x7031567681e76299,
	0x8977338cd4e2a93d, 0x8a5708a1d4c02b61,
	0x2066296a21501019, 0x9e260d94a4d775b1,
	0xe7667bbd72280f4d, 0x12df4035e1684349]

X = [2 + i for i in range(len(enc))]
s = Solver()

flag = [BitVec('flag[%d]' % i, 64) for i in range(43)]

X = [BitVecVal(x, 64) for x in X]
enc = [BitVecVal(enc, 64) for enc in enc]

for i in range(5, 42):
    # s.add(flag[i] >= 0x20)
    # s.add(flag[i] <= 0x7e)
    # a-zA-Z0-9_
    s.add(Or(And(flag[i] >= 0x30, flag[i] <= 0x39),
             And(flag[i] >= 0x41, flag[i] <= 0x5a),
             And(flag[i] >= 0x61, flag[i] <= 0x7a),
             flag[i] == ord('_')))


s.add(flag[0] == ord('i'))
s.add(flag[1] == ord('c'))
s.add(flag[2] == ord('t'))
s.add(flag[3] == ord('f'))
s.add(flag[4] == ord('{'))
s.add(flag[42] == ord('}'))

for x, enc in zip(X, enc):
    m = 0
    for i in range(43):
        m *= x
        m += flag[i]

    s.add(m == enc)


if s.check() == sat:
    m = s.model()
    print(''.join([chr(m[flag[i]].as_long()) for i in range(43)]))
else:
    print('unsat')
    
