//! Resolve the task and file fields needed by the access hooks. Aya 0.14
//! exposes BTF serialization, but not member/type accessors. Keep this bounded
//! reader independent of the generated, kernel-config-specific vmlinux.rs.
//! Format: https://docs.kernel.org/bpf/btf.html
use cardwire_policy::{FileLayout, TaskLayout};

type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn word(self, bytes: &[u8], offset: usize) -> Result<u32> {
        let end = offset.checked_add(4).ok_or("BTF word overflow")?;
        let word: [u8; 4] = bytes
            .get(offset..end)
            .ok_or("Truncated BTF word")?
            .try_into()
            .map_err(|_| "Truncated BTF word")?;
        Ok(match self {
            Self::Little => u32::from_le_bytes(word),
            Self::Big => u32::from_be_bytes(word),
        })
    }
}

struct Type<'a> {
    name: u32,
    info: u32,
    size_type: u32,
    payload: &'a [u8],
}

impl Type<'_> {
    fn kind(&self) -> u32 {
        (self.info >> 24) & 0x7f
    }
}

struct Btf<'a> {
    endian: Endian,
    strings: &'a [u8],
    types: Vec<Type<'a>>,
}

#[derive(Clone, Copy, Debug)]
struct Field {
    type_id: u32,
    offset: u32,
}

impl<'a> Btf<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > 64 * 1024 * 1024 {
            return Err("BTF exceeds size limit");
        }
        let endian = match bytes.get(..4) {
            Some([0x9f, 0xeb, 1, 0]) => Endian::Little,
            Some([0xeb, 0x9f, 1, 0]) => Endian::Big,
            _ => return Err("Unsupported BTF magic, version or flags"),
        };
        let header = endian.word(bytes, 4)? as usize;
        if header < 24 || header > bytes.len() {
            return Err("Invalid BTF header length");
        }
        let section = |offset, length| -> Result<(usize, usize)> {
            let start = header
                .checked_add(endian.word(bytes, offset)? as usize)
                .ok_or("BTF section overflow")?;
            let end = start
                .checked_add(endian.word(bytes, length)? as usize)
                .ok_or("BTF section overflow")?;
            if bytes.get(start..end).is_none() {
                return Err("BTF section outside input");
            }
            Ok((start, end))
        };
        let (type_start, type_end) = section(8, 12)?;
        let (string_start, string_end) = section(16, 20)?;
        if type_start < string_end && string_start < type_end {
            return Err("Overlapping BTF sections");
        }
        let strings = &bytes[string_start..string_end];
        if strings.first() != Some(&0) || strings.last() != Some(&0) {
            return Err("Invalid BTF string table");
        }
        let mut types = Vec::new();
        let data = &bytes[type_start..type_end];
        let mut cursor = 0;
        while cursor < data.len() {
            if types.len() >= 0xfffff {
                return Err("Too many BTF types");
            }
            let name = endian.word(data, cursor)?;
            let info = endian.word(data, cursor + 4)?;
            let size_type = endian.word(data, cursor + 8)?;
            let count = (info & 0xffffff) as usize;
            let payload_len = match (info >> 24) & 0x7f {
                1 | 14 | 17 => 4,
                2 | 7..=12 | 16 | 18 => 0,
                3 => 12,
                4 | 5 | 15 | 19 => count.checked_mul(12).ok_or("BTF payload overflow")?,
                6 | 13 => count.checked_mul(8).ok_or("BTF payload overflow")?,
                _ => return Err("Unsupported BTF type kind"),
            };
            cursor += 12;
            let end = cursor
                .checked_add(payload_len)
                .ok_or("BTF payload overflow")?;
            let payload = data.get(cursor..end).ok_or("Truncated BTF type payload")?;
            types.push(Type {
                name,
                info,
                size_type,
                payload,
            });
            cursor = end;
        }
        Ok(Self {
            endian,
            strings,
            types,
        })
    }

    fn name(&self, offset: u32) -> Result<&[u8]> {
        let tail = self
            .strings
            .get(offset as usize..)
            .ok_or("Invalid BTF string offset")?;
        let length = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or("Unterminated BTF string")?;
        Ok(&tail[..length])
    }

    fn get(&self, id: u32) -> Result<&Type<'a>> {
        let index = id.checked_sub(1).ok_or("Unexpected void type")? as usize;
        self.types.get(index).ok_or("Invalid BTF type reference")
    }

    fn resolve(&self, mut id: u32) -> Result<(u32, &Type<'a>)> {
        for _ in 0..32 {
            let ty = self.get(id)?;
            if matches!(ty.kind(), 8..=11 | 18) {
                id = ty.size_type;
            } else {
                return Ok((id, ty));
            }
        }
        Err("Cyclic or excessive BTF qualifiers")
    }

    fn named_struct(&self, name: &[u8]) -> Result<(u32, &Type<'a>)> {
        let mut found = None;
        for (index, ty) in self.types.iter().enumerate() {
            if ty.kind() == 4
                && self.name(ty.name)? == name
                && found.replace((index as u32 + 1, ty)).is_some()
            {
                return Err("Ambiguous kernel structure");
            }
        }
        found.ok_or("Missing kernel structure")
    }

    fn field(&self, id: u32, path: &[&[u8]]) -> Result<Field> {
        self.find_field(id, path, &mut Vec::new(), &mut 4096)?
            .ok_or("Missing kernel member")
    }

    // Follow embedded members, including anonymous unions/structs, never
    // pointer targets. Bound both recursion and total work across branches.
    fn find_field(
        &self,
        id: u32,
        path: &[&[u8]],
        stack: &mut Vec<u32>,
        budget: &mut u32,
    ) -> Result<Option<Field>> {
        let (id, ty) = self.resolve(id)?;
        if path.is_empty() || !matches!(ty.kind(), 4 | 5) {
            return Err("Expected an embedded aggregate member");
        }
        if stack.len() >= 32 || stack.contains(&id) || ty.size_type == 0 || ty.size_type > 65536 {
            return Err("Cyclic, oversized or excessive embedded structure");
        }
        stack.push(id);
        let mut found = None;
        for member in ty.payload.chunks_exact(12) {
            *budget = budget.checked_sub(1).ok_or("Excessive member lookup")?;
            let name = self.name(self.endian.word(member, 0)?)?;
            if !name.is_empty() && name != path[0] {
                continue;
            }
            let type_id = self.endian.word(member, 4)?;
            let (type_id, child) = self.resolve(type_id)?;
            // Anonymous scalar padding cannot contain the requested member.
            if name.is_empty() && !matches!(child.kind(), 4 | 5) {
                continue;
            }
            let bits = self.endian.word(member, 8)?;
            if ty.info >> 31 != 0 && bits >> 24 != 0 {
                return Err("Selected member must not be a bitfield");
            }
            let bits = if ty.info >> 31 != 0 {
                bits & 0xffffff
            } else {
                bits
            };
            if bits & 7 != 0 {
                return Err("Selected member must be byte-aligned");
            }
            let offset = bits / 8;
            let width = match child.kind() {
                2 => 8,
                1 | 4 | 5 => child.size_type,
                _ => return Err("Unsupported selected member type"),
            };
            if width == 0 || width > ty.size_type || offset > ty.size_type - width {
                return Err("Embedded member is outside its enclosing type");
            }
            let next = if name.is_empty() { path } else { &path[1..] };
            let candidate = if next.is_empty() {
                Some(Field { type_id, offset })
            } else {
                self.find_field(type_id, next, stack, budget)?
                    .map(|field| Field {
                        type_id: field.type_id,
                        offset: offset + field.offset,
                    })
            };
            if let Some(candidate) = candidate
                && found.replace(candidate).is_some()
            {
                return Err("Ambiguous embedded kernel member");
            }
        }
        stack.pop();
        Ok(found)
    }

    fn pointer_target(&self, field: Field) -> Result<u32> {
        let (_, ty) = self.resolve(field.type_id)?;
        if ty.kind() != 2 {
            return Err("Expected a kernel pointer member");
        }
        Ok(self.resolve(ty.size_type)?.0)
    }

    fn points_to(&self, field: Field, target: u32) -> Result<()> {
        if self.pointer_target(field)? != target {
            return Err("Kernel pointer has the wrong target type");
        }
        Ok(())
    }
}

pub(super) fn task_from_btf_bytes(bytes: &[u8]) -> Result<TaskLayout> {
    if std::mem::size_of::<usize>() != 8 {
        return Err("Only 64-bit kernel pointers are supported");
    }
    let btf = Btf::parse(bytes)?;
    let mut task = None;
    for (index, ty) in btf.types.iter().enumerate() {
        if ty.kind() == 4
            && btf.name(ty.name)? == b"task_struct"
            && task.replace((index as u32 + 1, ty)).is_some()
        {
            return Err("Ambiguous task_struct definition");
        }
    }
    let (task_id, task) = task.ok_or("Missing task_struct definition")?;
    let mut parent = None;
    let mut tgid = None;
    for member in task.payload.chunks_exact(12) {
        let name = btf.name(btf.endian.word(member, 0)?)?;
        let target = match name {
            b"real_parent" => &mut parent,
            b"tgid" => &mut tgid,
            _ => continue,
        };
        let type_id = btf.endian.word(member, 4)?;
        let encoded_offset = btf.endian.word(member, 8)?;
        let offset = if task.info >> 31 != 0 {
            if encoded_offset >> 24 != 0 {
                return Err("Task field must not be a bitfield");
            }
            encoded_offset & 0xffffff
        } else {
            encoded_offset
        };
        if offset & 7 != 0 || target.replace((type_id, offset / 8)).is_some() {
            return Err("Duplicate or bit-unaligned task field");
        }
    }
    let (parent_type_id, real_parent) = parent.ok_or("Missing real_parent field")?;
    let (tgid_type_id, tgid) = tgid.ok_or("Missing tgid field")?;
    let (_, parent_type) = btf.resolve(parent_type_id)?;
    if parent_type.kind() != 2 || btf.resolve(parent_type.size_type)?.0 != task_id {
        return Err("real_parent must point to this task_struct");
    }
    let (_, tgid_type) = btf.resolve(tgid_type_id)?;
    if tgid_type.kind() != 1
        || tgid_type.size_type != 4
        || btf.endian.word(tgid_type.payload, 0)? != (1 << 24) | 32
    {
        return Err("tgid must be a signed 32-bit integer");
    }
    let layout = TaskLayout {
        size: task.size_type,
        real_parent,
        tgid,
    };
    if !layout.is_valid() {
        return Err("Task field bounds, alignment or overlap are invalid");
    }
    Ok(layout)
}

pub(super) fn files_from_btf_bytes(bytes: &[u8]) -> Result<FileLayout> {
    if std::mem::size_of::<usize>() != 8 {
        return Err("Only 64-bit kernel pointers are supported");
    }
    let btf = Btf::parse(bytes)?;
    let (inode_id, inode) = btf.named_struct(b"inode")?;
    let (dentry_id, dentry) = btf.named_struct(b"dentry")?;
    let (file_id, file) = btf.named_struct(b"file")?;
    let (path_id, path) = btf.named_struct(b"path")?;
    let (hlist_id, hlist) = btf.named_struct(b"hlist_node")?;
    if hlist.size_type != 16 {
        return Err("Unsupported hlist_node size");
    }
    let inode_number = btf.field(inode_id, &[b"i_ino"])?;
    let (_, ino_type) = btf.resolve(inode_number.type_id)?;
    if ino_type.kind() != 1
        || ino_type.size_type != 8
        || btf.endian.word(ino_type.payload, 0)? != 64
    {
        return Err("inode number must be an unsigned 64-bit integer");
    }
    let inode_alias = btf.field(inode_id, &[b"i_dentry", b"first"])?;
    btf.points_to(inode_alias, hlist_id)?;
    let dentry_inode = btf.field(dentry_id, &[b"d_inode"])?;
    btf.points_to(dentry_inode, inode_id)?;
    let dentry_name = btf.field(dentry_id, &[b"d_name", b"name"])?;
    let (_, char_type) = btf.resolve(btf.pointer_target(dentry_name)?)?;
    if char_type.kind() != 1
        || char_type.size_type != 1
        || !matches!(btf.endian.word(char_type.payload, 0)?, 8 | 0x02000008)
    {
        return Err("dentry name must point to unsigned characters");
    }
    // Older kernels name the union d_u; newer kernels make it anonymous.
    // Reject both being present instead of guessing which alias to use.
    let direct = btf.find_field(dentry_id, &[b"d_alias"], &mut Vec::new(), &mut 4096)?;
    let nested = btf.find_field(dentry_id, &[b"d_u", b"d_alias"], &mut Vec::new(), &mut 4096)?;
    let dentry_alias = match (direct, nested) {
        (Some(field), None) | (None, Some(field)) => field,
        _ => return Err("Missing or ambiguous dentry alias"),
    };
    if btf.resolve(dentry_alias.type_id)?.0 != hlist_id {
        return Err("dentry alias must be an embedded hlist_node");
    }
    if btf.resolve(btf.field(file_id, &[b"f_path"])?.type_id)?.0 != path_id {
        return Err("file path must be the kernel path structure");
    }
    let file_dentry = btf.field(file_id, &[b"f_path", b"dentry"])?;
    btf.points_to(file_dentry, dentry_id)?;
    let path_dentry = btf.field(path_id, &[b"dentry"])?;
    btf.points_to(path_dentry, dentry_id)?;
    let layout = FileLayout {
        inode_size: inode.size_type,
        inode_number: inode_number.offset,
        inode_alias: inode_alias.offset,
        dentry_size: dentry.size_type,
        dentry_inode: dentry_inode.offset,
        dentry_name: dentry_name.offset,
        dentry_alias: dentry_alias.offset,
        file_size: file.size_type,
        file_dentry: file_dentry.offset,
        path_size: path.size_type,
        path_dentry: path_dentry.offset,
    };
    if !layout.is_valid() {
        return Err("File member bounds, alignment or overlap are invalid");
    }
    Ok(layout)
}

#[cfg(test)]
mod tests {
    use super::{task_from_btf_bytes as from_btf_bytes, *};

    fn word(output: &mut Vec<u8>, value: u32, endian: Endian) {
        output.extend(match endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        });
    }

    fn wrap(types: &[u8], strings: &[u8], endian: Endian) -> Vec<u8> {
        let mut result = match endian {
            Endian::Little => vec![0x9f, 0xeb, 1, 0],
            Endian::Big => vec![0xeb, 0x9f, 1, 0],
        };
        for value in [
            24,
            0,
            types.len() as u32,
            types.len() as u32,
            strings.len() as u32,
        ] {
            word(&mut result, value, endian);
        }
        result.extend(types);
        result.extend(strings);
        result
    }

    fn fixture(endian: Endian, layout: TaskLayout) -> Vec<u8> {
        let strings = b"\0int\0pid_t\0task_struct\0real_parent\0tgid\0";
        let mut types = Vec::new();
        // 1: signed int; 2: pid_t alias; 3: pointer to 4; 4: task_struct.
        for value in [
            1,
            1 << 24,
            4,
            (1 << 24) | 32,
            5,
            8 << 24,
            1,
            0,
            2 << 24,
            4,
            11,
            (4 << 24) | 2,
            layout.size,
            23,
            3,
            layout.real_parent * 8,
            35,
            2,
            layout.tgid * 8,
        ] {
            word(&mut types, value, endian);
        }
        assert_eq!(types.len(), 76);
        wrap(&types, strings, endian)
    }

    fn sample() -> Vec<u8> {
        fixture(
            Endian::Little,
            TaskLayout {
                size: 4032,
                real_parent: 1936,
                tgid: 1924,
            },
        )
    }

    fn set(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn resolves_both_observed_kernels_in_both_byte_orders() {
        for endian in [Endian::Little, Endian::Big] {
            for expected in [
                TaskLayout {
                    size: 4032,
                    real_parent: 1936,
                    tgid: 1924,
                },
                TaskLayout {
                    size: 6144,
                    real_parent: 2944,
                    tgid: 2932,
                },
            ] {
                assert_eq!(from_btf_bytes(&fixture(endian, expected)), Ok(expected));
            }
        }
    }

    #[test]
    fn every_truncated_prefix_is_rejected() {
        let bytes = sample();
        for length in 0..bytes.len() {
            assert!(from_btf_bytes(&bytes[..length]).is_err(), "length={length}");
        }
    }

    #[test]
    fn malformed_sections_and_header_are_rejected() {
        for (offset, value) in [
            (4, 23),
            (4, u32::MAX),
            (8, u32::MAX),
            (12, u32::MAX),
            (16, 0),
            (16, u32::MAX),
            (20, u32::MAX),
        ] {
            let mut bytes = sample();
            set(&mut bytes, offset, value);
            assert!(from_btf_bytes(&bytes).is_err(), "offset={offset}");
        }
        for offset in 0..4 {
            let mut bytes = sample();
            bytes[offset] ^= 0xff;
            assert!(from_btf_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn unknown_kind_oversized_payload_and_bad_strings_are_rejected() {
        for (offset, value) in [
            (28, 20 << 24),
            (68, (4 << 24) | 0xffffff),
            (64, u32::MAX),
            (76, u32::MAX),
            (88, u32::MAX),
        ] {
            let mut bytes = sample();
            set(&mut bytes, offset, value);
            assert!(from_btf_bytes(&bytes).is_err(), "offset={offset}");
        }
        let mut bytes = sample();
        *bytes.last_mut().unwrap() = b'X';
        assert!(from_btf_bytes(&bytes).is_err());
    }

    #[test]
    fn missing_or_ambiguous_struct_is_rejected() {
        let mut bytes = sample();
        set(&mut bytes, 64, 0);
        assert!(from_btf_bytes(&bytes).is_err());
        let bytes = sample();
        let mut types = bytes[24..100].to_vec();
        types.extend(&bytes[64..100]);
        assert!(from_btf_bytes(&wrap(&types, &bytes[100..], Endian::Little)).is_err());
    }

    #[test]
    fn missing_or_duplicate_members_are_rejected() {
        for (offset, value) in [(76, 0), (88, 0), (88, 23)] {
            let mut bytes = sample();
            set(&mut bytes, offset, value);
            assert!(from_btf_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn pointer_and_pid_types_are_checked_not_only_field_names() {
        for (offset, value) in [
            (80, 2),
            (60, 1),
            (92, 3),
            (36, 32),
            (36, (1 << 24) | 16),
            (32, 8),
            (80, u32::MAX),
        ] {
            let mut bytes = sample();
            set(&mut bytes, offset, value);
            assert!(
                from_btf_bytes(&bytes).is_err(),
                "offset={offset}, value={value}"
            );
        }
    }

    #[test]
    fn cyclic_dangling_and_void_aliases_are_rejected() {
        for value in [0, 2, u32::MAX] {
            let mut bytes = sample();
            set(&mut bytes, 48, value);
            assert!(from_btf_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn qualifiers_and_struct_flag_with_plain_members_are_supported() {
        let expected = from_btf_bytes(&sample()).unwrap();
        for kind in [8, 9, 10, 11, 18] {
            let mut bytes = sample();
            set(&mut bytes, 44, kind << 24);
            set(&mut bytes, 68, (1 << 31) | (4 << 24) | 2);
            assert_eq!(from_btf_bytes(&bytes), Ok(expected));
        }
    }

    #[test]
    fn bitfields_misalignment_overlap_and_bounds_are_rejected() {
        for (offset, value) in [
            (84, 1936 * 8 + 1),
            (84, 1937 * 8),
            (96, 1925 * 8),
            (96, 1940 * 8),
            (84, 4032 * 8),
            (96, 4032 * 8),
            (84, 0),
            (96, 0),
            (72, 0),
            (72, u32::MAX),
        ] {
            let mut bytes = sample();
            set(&mut bytes, offset, value);
            assert!(
                from_btf_bytes(&bytes).is_err(),
                "offset={offset}, value={value}"
            );
        }
        let mut bytes = sample();
        set(&mut bytes, 68, (1 << 31) | (4 << 24) | 2);
        set(&mut bytes, 96, (1 << 24) | (1924 * 8));
        assert!(from_btf_bytes(&bytes).is_err());
    }

    #[test]
    fn malformed_input_never_panics() {
        let bytes = sample();
        for offset in 0..bytes.len() {
            let mut mutated = bytes.clone();
            mutated[offset] ^= 0x80;
            let _ = from_btf_bytes(&mutated);
        }
    }

    struct FilesFixture {
        records: Vec<Vec<u32>>,
        strings: Vec<u8>,
        expected: FileLayout,
    }

    impl FilesFixture {
        fn string(&mut self, name: &str) -> u32 {
            let offset = self.strings.len() as u32;
            self.strings.extend(name.as_bytes());
            self.strings.push(0);
            offset
        }

        fn aggregate(&mut self, name: &str, kind: u32, size: u32, members: &[(&str, u32, u32)]) {
            let mut record = vec![self.string(name), kind << 24 | members.len() as u32, size];
            for (name, id, offset) in members {
                record.extend([self.string(name), *id, offset * 8]);
            }
            self.records.push(record);
        }

        fn new(inode_size: u32, inode_alias: u32, named_union: bool) -> Self {
            let mut f = Self {
                records: Vec::new(),
                strings: vec![0],
                expected: FileLayout {
                    inode_size,
                    inode_number: 64,
                    inode_alias,
                    dentry_size: 192,
                    dentry_inode: 48,
                    dentry_name: 40,
                    dentry_alias: 176,
                    file_size: 256,
                    file_dentry: 72,
                    path_size: 16,
                    path_dentry: 8,
                },
            };
            f.records.extend([
                vec![0, 1 << 24, 8, 64],         // 1: unsigned long
                vec![0, 1 << 24, 1, 0x02000008], // 2: unsigned char
                vec![0, 10 << 24, 2],            // 3: const char
                vec![0, 2 << 24, 3],             // 4: const char *
            ]);
            f.aggregate("hlist_node", 4, 16, &[("next", 6, 0), ("pprev", 7, 8)]); // 5
            f.records.extend([vec![0, 2 << 24, 5], vec![0, 2 << 24, 6]]); // 6, 7
            f.aggregate("hlist_head", 4, 8, &[("first", 6, 0)]); // 8
            f.aggregate("qstr", 4, 16, &[("name", 4, 8)]); // 9
            f.aggregate(
                "inode",
                4,
                inode_size,
                &[("i_ino", 1, 64), ("", 11, inode_alias)],
            ); // 10
            f.aggregate("", 5, 16, &[("i_dentry", 8, 0)]); // 11
            f.aggregate(
                "dentry",
                4,
                192,
                &[
                    ("d_inode", 13, 48),
                    ("d_name", 9, 32),
                    (if named_union { "d_u" } else { "" }, 14, 176),
                ],
            ); // 12
            f.records.push(vec![0, 2 << 24, 10]); // 13
            f.aggregate("", 5, 16, &[("d_alias", 5, 0)]); // 14
            f.aggregate("path", 4, 16, &[("dentry", 16, 8)]); // 15
            f.records.push(vec![0, 2 << 24, 12]); // 16
            f.aggregate("file", 4, 256, &[("f_path", 15, 64)]); // 17
            f
        }

        fn bytes(&self, endian: Endian) -> Vec<u8> {
            let mut types = Vec::new();
            for record in &self.records {
                for value in record {
                    word(&mut types, *value, endian);
                }
            }
            wrap(&types, &self.strings, endian)
        }
    }

    #[test]
    fn file_layout_resolves_observed_kernels_and_both_union_forms() {
        for endian in [Endian::Little, Endian::Big] {
            for (size, alias) in [(608, 304), (560, 296), (568, 296)] {
                for named in [false, true] {
                    let f = FilesFixture::new(size, alias, named);
                    assert_eq!(files_from_btf_bytes(&f.bytes(endian)), Ok(f.expected));
                }
            }
        }
    }

    #[test]
    fn file_layout_rejects_truncation_and_survives_byte_mutations() {
        let bytes = FilesFixture::new(608, 304, false).bytes(Endian::Little);
        for length in 0..bytes.len() {
            assert!(files_from_btf_bytes(&bytes[..length]).is_err());
        }
        for offset in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[offset] ^= 0x80;
            let _ = files_from_btf_bytes(&bad);
        }
    }

    #[test]
    fn file_layout_checks_types_alignment_bounds_and_cycles() {
        // Record indices are zero based; type references in BTF are one based.
        for (record, field, value) in [
            (0, 3, (1 << 24) | 64), // signed inode number
            (1, 3, (1 << 24) | 8),  // signed name characters
            (2, 2, 3),              // qualifier cycle
            (3, 2, 1),              // name points to u64
            (4, 2, 8),              // short hlist_node
            (5, 2, 10),             // first points to inode, not hlist_node
            (9, 2, u32::MAX),       // huge inode
            (9, 4, 4),              // i_ino is a pointer
            (9, 5, 65 * 8),         // misaligned inode number
            (9, 8, 64 * 8),         // inode fields overlap
            (9, 8, 608 * 8),        // embedded union outside inode
            (10, 4, 11),            // recursive anonymous aggregate
            (11, 4, 16),            // d_inode points to dentry
            (11, 8, 40 * 8),        // d_name.name overlaps d_inode
            (11, 11, 184 * 8),      // alias beyond dentry
            (13, 4, 6),             // alias pointer instead of embedded node
            (14, 4, 13),            // path points to inode
            (16, 4, 9),             // f_path is qstr
            (16, 5, 64 * 8 + 1),    // bit-unaligned file path
        ] {
            let mut f = FilesFixture::new(608, 304, false);
            f.records[record][field] = value;
            assert!(
                files_from_btf_bytes(&f.bytes(Endian::Little)).is_err(),
                "record={record}, field={field}, value={value}"
            );
        }
    }

    #[test]
    fn file_layout_rejects_selected_bitfields_but_ignores_unrelated_padding() {
        let mut f = FilesFixture::new(608, 304, false);
        f.records[9][1] |= 1 << 31;
        f.records[9][5] |= 1 << 24;
        assert!(files_from_btf_bytes(&f.bytes(Endian::Little)).is_err());
        f.records[9][5] &= 0xffffff;
        f.records[9][1] += 1;
        f.records[9].extend([0, 1, (1 << 24) | 17]);
        assert_eq!(
            files_from_btf_bytes(&f.bytes(Endian::Little)),
            Ok(f.expected)
        );
    }

    #[test]
    fn file_layout_rejects_duplicate_structs_and_ambiguous_members() {
        let mut f = FilesFixture::new(608, 304, false);
        f.records.push(f.records[9].clone());
        assert!(files_from_btf_bytes(&f.bytes(Endian::Little)).is_err());
        let mut f = FilesFixture::new(608, 304, false);
        f.records[9][1] += 1;
        let duplicate = f.records[9][3..6].to_vec();
        f.records[9].extend(duplicate);
        assert!(files_from_btf_bytes(&f.bytes(Endian::Little)).is_err());
        let mut f = FilesFixture::new(608, 304, true);
        f.records[11][1] += 1;
        f.records[11].extend([0, 14, 176 * 8]);
        assert!(files_from_btf_bytes(&f.bytes(Endian::Little)).is_err());
    }

    #[test]
    fn embedded_lookup_is_bounded_and_rejects_missing_members() {
        let f = FilesFixture::new(608, 304, false);
        let bytes = f.bytes(Endian::Little);
        let btf = Btf::parse(&bytes).unwrap();
        assert!(btf.field(10, &[b"missing"]).is_err());
        assert!(
            btf.find_field(10, &[b"i_ino"], &mut Vec::new(), &mut 0)
                .is_err()
        );
        assert!(
            btf.find_field(10, &[b"i_ino"], &mut vec![10], &mut 4096)
                .is_err()
        );
    }
}
