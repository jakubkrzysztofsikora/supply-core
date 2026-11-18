use anyhow::{bail, Context, Result};
use base64::Engine;
use sha2::{Digest, Sha512};

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const CENTRAL_HEADER_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_HEADER_SIGNATURE: u32 = 0x0403_4b50;
const SIGNATURE_ENTRY_NAME: &[u8] = b".signature.p7s";

#[derive(Clone, Copy)]
struct CentralEntry {
    position: usize,
    header_size: usize,
    local_offset: usize,
    file_size: usize,
    offset_delta: i64,
    is_signature: bool,
}

pub fn package_content_hash(archive: &[u8]) -> Result<String> {
    let eocd = find_eocd(archive)?;
    let disk_number = read_u16(archive, eocd + 4)?;
    let central_disk = read_u16(archive, eocd + 6)?;
    let disk_entries = read_u16(archive, eocd + 8)?;
    let total_entries = read_u16(archive, eocd + 10)?;
    let central_size = read_u32(archive, eocd + 12)? as usize;
    let central_offset = read_u32(archive, eocd + 16)? as usize;
    let comment_size = read_u16(archive, eocd + 20)? as usize;

    if disk_number != 0
        || central_disk != 0
        || disk_entries != total_entries
        || disk_entries == u16::MAX
        || total_entries == u16::MAX
        || central_size == u32::MAX as usize
        || central_offset == u32::MAX as usize
    {
        bail!("NuGet package uses an unsupported multi-disk or ZIP64 archive");
    }
    if eocd + 22 + comment_size != archive.len() || total_entries == 0 {
        bail!("NuGet package has an invalid ZIP end-of-central-directory record");
    }
    let central_end = central_offset
        .checked_add(central_size)
        .context("NuGet ZIP central-directory offset overflow")?;
    if central_end != eocd {
        bail!("NuGet package has an invalid ZIP central-directory range");
    }

    let mut entries = Vec::with_capacity(total_entries as usize);
    let mut position = central_offset;
    let mut signature_index = None;
    for _ in 0..total_entries {
        if read_u32(archive, position)? != CENTRAL_HEADER_SIGNATURE {
            bail!("NuGet package has an invalid ZIP central-directory entry");
        }
        let flags = read_u16(archive, position + 8)?;
        let name_size = read_u16(archive, position + 28)? as usize;
        let extra_size = read_u16(archive, position + 30)? as usize;
        let entry_comment_size = read_u16(archive, position + 32)? as usize;
        let header_size = 46_usize
            .checked_add(name_size)
            .and_then(|size| size.checked_add(extra_size))
            .and_then(|size| size.checked_add(entry_comment_size))
            .context("NuGet ZIP central-directory entry size overflow")?;
        let name_start = position
            .checked_add(46)
            .context("NuGet ZIP central-directory position overflow")?;
        let name_end = name_start
            .checked_add(name_size)
            .context("NuGet ZIP central-directory name size overflow")?;
        let name = range(archive, name_start, name_end)?;
        let local_offset = read_u32(archive, position + 42)? as usize;
        if local_offset == u32::MAX as usize {
            bail!("NuGet package uses an unsupported ZIP64 local-header offset");
        }
        if read_u32(archive, local_offset)? != LOCAL_HEADER_SIGNATURE {
            bail!("NuGet package has an invalid ZIP local-file header");
        }
        let is_signature = flags & 0x0800 == 0 && name == SIGNATURE_ENTRY_NAME;
        if is_signature {
            if signature_index.is_some() {
                bail!("NuGet package contains multiple signature entries");
            }
            signature_index = Some(entries.len());
        }
        entries.push(CentralEntry {
            position,
            header_size,
            local_offset,
            file_size: 0,
            offset_delta: 0,
            is_signature,
        });
        position = position
            .checked_add(header_size)
            .context("NuGet ZIP central-directory position overflow")?;
        if position > central_end {
            bail!("NuGet package has a truncated ZIP central directory");
        }
    }
    if position != central_end {
        bail!("NuGet package has trailing data in its ZIP central directory");
    }

    let signature_index = match signature_index {
        Some(index) => index,
        None => return Ok(hash(archive)),
    };
    let signature_header_size = entries[signature_index].header_size;

    let mut local_order: Vec<usize> = (0..entries.len()).collect();
    local_order.sort_unstable_by_key(|index| entries[*index].local_offset);
    for (order, index) in local_order.iter().enumerate() {
        let offset = entries[*index].local_offset;
        let next_offset = local_order
            .get(order + 1)
            .map(|next| entries[*next].local_offset)
            .unwrap_or(central_offset);
        if offset >= next_offset || next_offset > central_offset {
            bail!("NuGet package has overlapping ZIP local-file entries");
        }
        entries[*index].file_size = next_offset - offset;
    }

    let mut previous_end = 0_i64;
    for index in local_order.iter().copied() {
        if entries[index].is_signature {
            continue;
        }
        let entry = &mut entries[index];
        let local_offset = i64::try_from(entry.local_offset)
            .context("NuGet ZIP local-file offset exceeds supported range")?;
        entry.offset_delta = previous_end - local_offset;
        previous_end = local_offset
            + i64::try_from(entry.file_size)
                .context("NuGet ZIP local-file size exceeds supported range")?
            + entry.offset_delta;
    }

    let first_local_offset = entries
        .iter()
        .map(|entry| entry.local_offset)
        .min()
        .context("NuGet package has no ZIP local-file entries")?;
    let mut hasher = Sha512::new();
    hasher.update(range(archive, 0, first_local_offset)?);
    for index in local_order
        .iter()
        .copied()
        .filter(|index| !entries[*index].is_signature)
    {
        let entry = entries[index];
        let end = entry
            .local_offset
            .checked_add(entry.file_size)
            .context("NuGet ZIP local-file range overflow")?;
        hasher.update(range(archive, entry.local_offset, end)?);
    }

    for entry in entries.iter().filter(|entry| !entry.is_signature) {
        let fixed_end = entry
            .position
            .checked_add(42)
            .context("NuGet ZIP central-directory position overflow")?;
        hasher.update(range(archive, entry.position, fixed_end)?);
        let original_offset = i64::from(read_u32(archive, fixed_end)?);
        let adjusted_offset = original_offset + entry.offset_delta;
        let adjusted_offset = u32::try_from(adjusted_offset)
            .context("NuGet ZIP local-header offset adjustment is invalid")?;
        hasher.update(adjusted_offset.to_le_bytes());
        let entry_end = entry
            .position
            .checked_add(entry.header_size)
            .context("NuGet ZIP central-directory entry range overflow")?;
        hasher.update(range(archive, fixed_end + 4, entry_end)?);
    }

    let signature_entry = entries[signature_index];
    hasher.update(range(archive, eocd, eocd + 8)?);
    let adjusted_disk_entries = disk_entries
        .checked_sub(1)
        .context("NuGet ZIP entry count underflow")?;
    let adjusted_total_entries = total_entries
        .checked_sub(1)
        .context("NuGet ZIP entry count underflow")?;
    hasher.update(adjusted_disk_entries.to_le_bytes());
    hasher.update(adjusted_total_entries.to_le_bytes());
    let adjusted_central_size = u32::try_from(
        central_size
            .checked_sub(signature_header_size)
            .context("NuGet ZIP central-directory size underflow")?,
    )
    .context("NuGet ZIP central-directory size exceeds supported range")?;
    hasher.update(adjusted_central_size.to_le_bytes());
    let adjusted_central_offset = u32::try_from(
        central_offset
            .checked_sub(signature_entry.file_size)
            .context("NuGet ZIP central-directory offset underflow")?,
    )
    .context("NuGet ZIP central-directory offset exceeds supported range")?;
    hasher.update(adjusted_central_offset.to_le_bytes());
    hasher.update(range(archive, eocd + 20, archive.len())?);

    Ok(base64::engine::general_purpose::STANDARD.encode(hasher.finalize()))
}

fn find_eocd(archive: &[u8]) -> Result<usize> {
    if archive.len() < 22 {
        bail!("NuGet package is not a valid ZIP archive");
    }
    let search_start = archive.len().saturating_sub(22 + u16::MAX as usize);
    for position in (search_start..=archive.len() - 22).rev() {
        if read_u32(archive, position)? == EOCD_SIGNATURE {
            let comment_size = read_u16(archive, position + 20)? as usize;
            if position + 22 + comment_size == archive.len() {
                return Ok(position);
            }
        }
    }
    bail!("NuGet package is missing a ZIP end-of-central-directory record")
}

fn range(archive: &[u8], start: usize, end: usize) -> Result<&[u8]> {
    if start > end {
        bail!("invalid NuGet ZIP byte range");
    }
    archive
        .get(start..end)
        .context("NuGet package contains a truncated ZIP record")
}

fn read_u16(archive: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .context("NuGet ZIP field offset overflow")?;
    let bytes = range(archive, offset, end)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(archive: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .context("NuGet ZIP field offset overflow")?;
    let bytes = range(archive, offset, end)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn hash(archive: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(Sha512::digest(archive))
}
#[cfg(test)]
mod tests {
    use super::package_content_hash;
    use anyhow::Result;

    struct ArchiveFixture {
        bytes: Vec<u8>,
        payload_offset: usize,
        signature_offset: usize,
    }

    #[test]
    fn signed_content_hash_matches_nuget_reference() -> Result<()> {
        let fixture = signed_archive()?;
        assert_eq!(
            package_content_hash(&fixture.bytes)?,
            "QTxE1Prpu+BbZeqkiC4RIVJDF/Q4Toxn2JuQg+yaEnLpmxrIkwj+HnKtrMoq554chPk1yuRkgkAB/H6dkeWi6g=="
        );
        Ok(())
    }

    #[test]
    fn signed_content_hash_ignores_signature_but_detects_payload_changes() -> Result<()> {
        let fixture = signed_archive()?;
        let original_hash = package_content_hash(&fixture.bytes)?;

        let mut changed_signature = fixture.bytes.clone();
        changed_signature[fixture.signature_offset] ^= 1;
        assert_eq!(package_content_hash(&changed_signature)?, original_hash);

        let mut changed_payload = fixture.bytes;
        changed_payload[fixture.payload_offset] ^= 1;
        assert_ne!(package_content_hash(&changed_payload)?, original_hash);
        Ok(())
    }

    fn signed_archive() -> Result<ArchiveFixture> {
        let files: [(&[u8], &[u8]); 2] = [
            (b"lib/net10.0/Sample.txt", b"payload-content"),
            (b".signature.p7s", b"signature-bytes"),
        ];
        let mut archive = Vec::new();
        let mut central_records = Vec::new();
        let mut payload_offset = 0;
        let mut signature_offset = 0;

        for (name, data) in files {
            let local_offset = u32::try_from(archive.len())?;
            if name == b"lib/net10.0/Sample.txt" {
                payload_offset = archive.len() + 30 + name.len();
            } else {
                signature_offset = archive.len() + 30 + name.len();
            }
            let checksum = crc32(data);
            push_u32(&mut archive, 0x0403_4b50);
            push_u16(&mut archive, 20);
            push_u16(&mut archive, 0);
            push_u16(&mut archive, 0);
            push_u16(&mut archive, 0);
            push_u16(&mut archive, 0);
            push_u32(&mut archive, checksum);
            push_u32(&mut archive, u32::try_from(data.len())?);
            push_u32(&mut archive, u32::try_from(data.len())?);
            push_u16(&mut archive, u16::try_from(name.len())?);
            push_u16(&mut archive, 0);
            archive.extend_from_slice(name);
            archive.extend_from_slice(data);

            let mut central = Vec::new();
            push_u32(&mut central, 0x0201_4b50);
            push_u16(&mut central, 20);
            push_u16(&mut central, 20);
            push_u16(&mut central, 0);
            push_u16(&mut central, 0);
            push_u16(&mut central, 0);
            push_u16(&mut central, 0);
            push_u32(&mut central, checksum);
            push_u32(&mut central, u32::try_from(data.len())?);
            push_u32(&mut central, u32::try_from(data.len())?);
            push_u16(&mut central, u16::try_from(name.len())?);
            push_u16(&mut central, 0);
            push_u16(&mut central, 0);
            push_u16(&mut central, 0);
            push_u16(&mut central, 0);
            push_u32(&mut central, 0);
            push_u32(&mut central, local_offset);
            central.extend_from_slice(name);
            central_records.push(central);
        }

        let central_offset = u32::try_from(archive.len())?;
        for record in &central_records {
            archive.extend_from_slice(record);
        }
        let central_size = u32::try_from(archive.len())? - central_offset;
        push_u32(&mut archive, 0x0605_4b50);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, u16::try_from(central_records.len())?);
        push_u16(&mut archive, u16::try_from(central_records.len())?);
        push_u32(&mut archive, central_size);
        push_u32(&mut archive, central_offset);
        push_u16(&mut archive, 0);

        Ok(ArchiveFixture {
            bytes: archive,
            payload_offset,
            signature_offset,
        })
    }

    fn push_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut checksum = u32::MAX;
        for byte in bytes {
            checksum ^= u32::from(*byte);
            for _ in 0..8 {
                let mask = 0_u32.wrapping_sub(checksum & 1);
                checksum = (checksum >> 1) ^ (0xedb8_8320 & mask);
            }
        }
        !checksum
    }
}
