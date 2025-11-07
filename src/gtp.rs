use nom::{
    IResult,
    number::complete::{be_u8, be_u16, be_u32},
    bytes::complete::take,
};

#[derive(Debug)]
pub struct GtpHeader<'a> {
    pub version: u8,
    pub p_flag: bool,
    pub t_flag: bool,
    pub mp_flag: bool,

    pub msg_type: u8,
    pub msg_len: u16,

    pub teid: Option<u32>,

    pub seq: u32,
    pub mp: Option<u8>,
    pub payload: &'a [u8],
}

#[derive(Debug)]
pub struct GtpIe<'a> {
    pub ie_type: u8,
    pub length: u16,
    pub instance: u8,
    pub value: &'a [u8],
}


pub fn parse_ie(input: &[u8]) -> IResult<&[u8], GtpIe>
{
    let (input, ie_type) = be_u8(input)?;
    let (input, ie_len) = be_u16(input)?;
    let (input, inst_byte) = be_u8(input)?;
    let ie_inst = inst_byte & 0x0f;

    let (input, ie_value) = take(ie_len)(input)?;

    Ok((input, GtpIe {
        ie_type,
        length :ie_len,
        instance: ie_inst,
        value: ie_value,
    }))
}

pub fn parse_all_ies(mut input: &[u8]) -> Vec<GtpIe> {
    let mut result = Vec::new();

    while !input.is_empty () {
        match parse_ie(input) {
            Ok((rest, ie)) => {
                result.push(ie);
                input = rest;
            },

            Err(_) => break,
        }
    }

    result
}

pub fn parse_gtpc(input: &[u8]) -> IResult<&[u8], GtpHeader>
{
    let (input, flags) = be_u8(input)?;
    let version = (flags >> 5) & 0x07;
    let p_flag = ((flags >> 4) & 0x01) == 1;
    let t_flag = ((flags >> 3) & 0x01) == 1;
    let mp_flag = ((flags >> 2) & 0x01) == 1;

    let (input, msg_type) = be_u8(input)?;
    let (input, msg_len) = be_u16(input)?;

    let (input, teid) = if t_flag {
        let (input, teid) = be_u32(input)?;
        (input, Some(teid))
    }
    else {
        (input, None)
    };

    let (input, seq_bytes) = take(3usize)(input)?;
    let seq = ((seq_bytes[0] as u32) << 16)
                   | ((seq_bytes[1] as u32) << 8)
                   | (seq_bytes[2] as u32);

    let (input, mp) = if mp_flag {
        let (input, m) = be_u8(input)?;
        let m = (m >> 4) & 0x0f;
        (input, Some(m))
    }
    else {
        (input, None)
    };

    let (remaining, payload) = take(msg_len as usize)(input)?;

    Ok (( remaining, GtpHeader {
        version,
        p_flag,
        t_flag,
        mp_flag,
        msg_type,
        msg_len,
        teid,
        seq,
        mp,
        payload,
    }))
}