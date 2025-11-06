use nom::{
    IResult,
    number::complete::{be_u8, be_u16, be_u32},
    bytes::complete::take,
};

#[derive(Debug)]
pub struct GtpHeader<'a> {
    pub version: u8,
    pub pt: bool,
    pub e: bool,
    pub s: bool,
    pub pn: bool,
    pub msg_type: u8,
    pub length: u16,
    pub teid: Option<u32>,
    pub seq: u32,
    pub payload: &'a [u8],
}

pub fn parse_gtpc(input: &[u8]) -> IResult<&[u8], GtpHeader> {
{

}