#ifndef FASTDDS_SECURITY_CRYPTOGRAPHY_AESGCMGMACFAST_EXTHANDLES_H
#define FASTDDS_SECURITY_CRYPTOGRAPHY_AESGCMGMACFAST_EXTHANDLES_H

#include <fastdds/rtps/security/cryptography/CryptoKeyFactory.h>
#include <fastdds/rtps/attributes/PropertyPolicy.h>

#include <security/cryptography/AESGCMGMACFAST_Types.h>
#include <security/cryptography/AESGCMGMAC_Types.h>

#include <memory>
#include <atomic>
#include <chrono>
#include <thread>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <openssl/evp.h>

namespace eprosima {
namespace fastrtps {
namespace rtps {
namespace security {

constexpr size_t BUFFER_SIZE = KEYSTREAM_SIZE * MAX_ROUND_SIZE;

struct CircularBuffer{
    unsigned char keystreams[BUFFER_SIZE][AES_GCM_BLOCK_SIZE];
    std::atomic<int> head;
    std::atomic<int> tail;
    std::atomic<bool> stop_round;
    std::atomic<int> session;
    std::atomic<int> last;

    CircularBuffer(uint32_t session_id, bool type) : head(0), tail(0), stop_round(false), last(MAX_ROUND_SIZE) {
        session.store(session_id, std::memory_order_release);
    }

    size_t remain_size() const
    {
        int h = head.load();
        int t = tail.load();

        if(h > t)
            return h - t;
        else
            return BUFFER_SIZE - t + h - 1;
    }

    size_t get_last()
    {
        return last.load();
    }

    void set_last(int l)
    {
        last.store(l);
    }

    bool push(EVP_CIPHER_CTX* ctx)
    {

        int block_cnt;
        uint32_t session_id = session.load(std::memory_order_acquire);

        //max_blocks_per_session
        for(int round = 0; round < MAX_ROUND_SIZE; round++){

            //max iv counter
            for(size_t i = 0; i < KEYSTREAM_SIZE; i += CHUNK_SIZE){
                if(stop_round.load(std::memory_order_acquire)){

                    int h = head.load(std::memory_order_acquire);
                    int t = tail.load(std::memory_order_acquire);
                    round += (h - t) / KEYSTREAM_SIZE;
                    add_gctx_ctr(ctx, h - t);
                    
                    tail.store(h, std::memory_order_release);
                    t = tail.load(std::memory_order_acquire);
                    stop_round.store(false, std::memory_order_release);
                    break;
                }
                 size_t cur_chunk = std::min(static_cast<size_t>(CHUNK_SIZE), KEYSTREAM_SIZE - i);

                int h = head.load(std::memory_order_acquire);
                int t = tail.load(std::memory_order_acquire);

                while(remain_size() <= cur_chunk){
                    std::this_thread::sleep_for(std::chrono::nanoseconds(WAIT_INTERVAL));
                }

                int cur_tail = t;
                size_t space_end = BUFFER_SIZE - cur_tail;

                if(space_end >= cur_chunk){
                    EVP_KeyGeneration(ctx, keystreams[t], &block_cnt, (const unsigned char *)"A", cur_chunk);
                } else{
                    EVP_KeyGeneration(ctx, keystreams[t], &block_cnt, (const unsigned char *)"A", space_end);
                    EVP_KeyGeneration(ctx, keystreams[0], &block_cnt, (const unsigned char *)"A", cur_chunk - space_end);
                }

                tail.store((t + cur_chunk) % BUFFER_SIZE);
            }
        }

        return true;
    }

    void move_head(int shift){
        int h = head.load(std::memory_order_acquire);
        int t = tail.load(std::memory_order_acquire);
        int new_head = (h + shift) % BUFFER_SIZE;

        if(BUFFER_SIZE - remain_size() < shift){
            head.store(new_head, std::memory_order_release);
            stop_round.store(true, std::memory_order_release);
        }
        
        while(stop_round.load()){
            std::this_thread::sleep_for(std::chrono::nanoseconds(WAIT_INTERVAL));
        }
        head.store(new_head, std::memory_order_release);
    }

    unsigned char * get_keystream(int len, int block_cnt, EVP_CIPHER_CTX * ctx)
    {
        uint32_t session_id = session.load(std::memory_order_acquire);
        int blocks_needed = (len + AES_GCM_BLOCK_SIZE - 1) / AES_GCM_BLOCK_SIZE;
        unsigned char *buf = (unsigned char (*))malloc(blocks_needed * AES_GCM_BLOCK_SIZE);
        if(!buf)
            return NULL;

        unsigned char* out_ptr = buf;
        int res = blocks_needed;
        int h, t;
        int l = last.load(std::memory_order_acquire);
        int diff = (l != MAX_ROUND_SIZE) ? block_cnt - l : block_cnt - 0;

        if(diff){
            int shift = diff * KEYSTREAM_SIZE;

            move_head(shift);
        }
        
        while(stop_round.load()){}

            while(res > 0){
                h = head.load(std::memory_order_acquire);
                t = tail.load(std::memory_order_acquire);

                int item_len = (h <= t) ? (t - h) : (BUFFER_SIZE - h + t);
                if(item_len <= 0) continue;

                int cnt = (item_len < res) ? item_len : res;

                int first_part = std::min<int>(cnt, BUFFER_SIZE - h);
                memcpy(out_ptr, keystreams[h], AES_GCM_BLOCK_SIZE * first_part);

                if(cnt > first_part){
                    memcpy(out_ptr + (first_part * AES_GCM_BLOCK_SIZE),
                            keystreams[0],
                            AES_GCM_BLOCK_SIZE * (cnt - first_part));
                }

                head.store((h + cnt) % BUFFER_SIZE, std::memory_order_release);
                res -= cnt;
                out_ptr += (cnt * AES_GCM_BLOCK_SIZE);
            }

         move_head((KEYSTREAM_SIZE - blocks_needed));
        
         last.store(block_cnt + 1, std::memory_order_release);

        return buf;
    }
};

struct AESGCMGMACFAST_WriterCryptoHandleImpl
    : public HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>
{
    using HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>::nil;
    using BaseType = HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>;

    std::shared_ptr<CircularBuffer> e_buffer;
    EVP_CIPHER_CTX* e_ctx = nullptr;
    uint32_t e_session = 0;
    std::array<uint8_t, 32> e_key{};

    std::shared_ptr<CircularBuffer> d_buffer;
    EVP_CIPHER_CTX* d_ctx = nullptr;
    uint32_t d_session = 0;
    std::array<uint8_t, 32> d_key{};

    static AESGCMGMACFAST_WriterCryptoHandleImpl& narrow(DatawriterCryptoHandle& handle)
    {
        return static_cast<AESGCMGMACFAST_WriterCryptoHandleImpl&>(
                BaseType::narrow(handle));
                
    }

    static BaseType& narrow_base(DatawriterCryptoHandle& handle)
    {
        return static_cast<BaseType&>(
                BaseType::narrow(handle));
    }
};
    
struct AESGCMGMACFAST_ReaderCryptoHandleImpl
    : public HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>
{
    using HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>::nil;
    using BaseType = HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>;

    static AESGCMGMACFAST_ReaderCryptoHandleImpl& narrow(DatawriterCryptoHandle& handle)
    {
        return static_cast<AESGCMGMACFAST_ReaderCryptoHandleImpl&>(
                HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>::narrow(handle));
    }

    static BaseType& narrow_base(DatawriterCryptoHandle& handle)
    {
        return static_cast<BaseType&>(
                BaseType::narrow(handle));
    }
};

struct AESGCMGMACFAST_EntityCryptoHandleImpl
    : public HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>
{
    using HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>::nil;

    static AESGCMGMACFAST_EntityCryptoHandleImpl& narrow(DatawriterCryptoHandle& handle)
    {
        return static_cast<AESGCMGMACFAST_EntityCryptoHandleImpl&>(
                HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>::narrow(handle));
    }
};
typedef AESGCMGMACFAST_WriterCryptoHandleImpl AESGCMGMACFAST_WriterCryptoHandle;
typedef AESGCMGMACFAST_ReaderCryptoHandleImpl AESGCMGMACFAST_ReaderCryptoHandle;
typedef AESGCMGMACFAST_EntityCryptoHandleImpl AESGCMGMACFAST_EntityCryptoHandle;
}
}
}
}

#endif
