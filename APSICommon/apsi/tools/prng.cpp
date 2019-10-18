#include "prng.h"

#include <algorithm>
#include <cstring>

#include "apsi/item.h"


using namespace std;
using namespace apsi;
using namespace apsi::tools;

PRNG::PRNG(const block& seed, size_t buffer_size)
    : bytes_idx_(0),
      block_idx_(0)
{
    set_seed(seed, buffer_size);
}

PRNG::PRNG(const Item& seed, size_t buffer_size)
    : bytes_idx_(0),
      block_idx_(0)
{
    // This works because Item is 128 bits. Ensure this is always true
    if (sizeof(block) != sizeof(Item))
    {
        throw std::runtime_error("Size of block and size of Item are different");
    }

    set_seed(_mm_set_epi64x(seed[1], seed[0]), buffer_size);
}

PRNG::PRNG(PRNG && s) :
    buffer_(std::move(s.buffer_)),
    aes_(std::move(s.aes_)),
    bytes_idx_(s.bytes_idx_),
    block_idx_(s.block_idx_),
    buffer_byte_capacity_(s.buffer_byte_capacity_)
{
    clear(s);
}

void PRNG::operator=(PRNG&&s)
{
    buffer_ = (std::move(s.buffer_));
    aes_ = (std::move(s.aes_));
    bytes_idx_ = s.bytes_idx_;
    block_idx_ = s.block_idx_;
    buffer_byte_capacity_ = s.buffer_byte_capacity_;
    
    clear(s);
}

void PRNG::set_seed(const block& seed, size_t buffer_size)
{
    aes_.set_key(seed);
    block_idx_ = 0;

    if (buffer_.size() == 0)
    {
        buffer_.resize(buffer_size);
        buffer_byte_capacity_ = (sizeof(block) * buffer_size);
    }

    refill_buffer();
}

u8 PRNG::get_bit()
{
    u8 ret = get<u8>();
    return (ret & 0x01);
}

block PRNG::get_seed() const
{
    if (buffer_.size())
        return aes_.get_key();

    throw std::runtime_error("PRNG has not been keyed ");
}

void PRNG::refill_buffer()
{
    if (buffer_.size() == 0)
        throw std::runtime_error("PRNG has not been keyed ");

    aes_.ecb_enc_counter_mode(block_idx_, buffer_.size(), buffer_.data());
    block_idx_ += buffer_.size();
    bytes_idx_ = 0;
}

void PRNG::clear(PRNG& p)
{
    p.buffer_.resize(0);
    p.aes_.clear();
    p.bytes_idx_ = 0;
    p.block_idx_ = 0;
    p.buffer_byte_capacity_ = 0;
}
