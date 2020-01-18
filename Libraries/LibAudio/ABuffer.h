/*
 * Copyright (c) 2018-2020, Andreas Kling <kling@serenityos.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#include <AK/ByteBuffer.h>
#include <AK/Types.h>
#include <AK/Vector.h>
#include <AK/SharedBuffer.h>

// A single sample in an audio buffer.
// Values are floating point, and should range from -1.0 to +1.0
struct ASample {
    ASample()
        : left(0)
        , right(0)
    {
    }

    // For mono
    ASample(float left)
        : left(left)
        , right(left)
    {
    }

    // For stereo
    ASample(float left, float right)
        : left(left)
        , right(right)
    {
    }

    void clip()
    {
        if (left > 1)
            left = 1;
        else if (left < -1)
            left = -1;

        if (right > 1)
            right = 1;
        else if (right < -1)
            right = -1;
    }

    void scale(int percent)
    {
        float pct = (float)percent / 100.0;
        left *= pct;
        right *= pct;
    }

    ASample& operator+=(const ASample& other)
    {
        left += other.left;
        right += other.right;
        return *this;
    }

    float left;
    float right;
};

// Small helper to resample from one playback rate to another
// This isn't really "smart", in that we just insert (or drop) samples.
// Should do better...
class AResampleHelper {
public:
    AResampleHelper(float source, float target);

    void process_sample(float sample_l, float sample_r);
    bool read_sample(float& next_l, float& next_r);

private:
    const float m_ratio;
    float m_current_ratio { 0 };
    float m_last_sample_l { 0 };
    float m_last_sample_r { 0 };
};

// A buffer of audio samples, normalized to 44100hz.
class ABuffer : public RefCounted<ABuffer> {
public:
    static RefPtr<ABuffer> from_pcm_data(ByteBuffer& data, AResampleHelper& resampler, int num_channels, int bits_per_sample);
    static NonnullRefPtr<ABuffer> create_with_samples(Vector<ASample>&& samples)
    {
        return adopt(*new ABuffer(move(samples)));
    }
    static NonnullRefPtr<ABuffer> create_with_shared_buffer(NonnullRefPtr<SharedBuffer>&& buffer, int sample_count)
    {
        return adopt(*new ABuffer(move(buffer), sample_count));
    }

    const ASample* samples() const { return (const ASample*)data(); }
    int sample_count() const { return m_sample_count; }
    const void* data() const { return m_buffer->data(); }
    int size_in_bytes() const { return m_sample_count * (int)sizeof(ASample); }
    int shared_buffer_id() const { return m_buffer->shared_buffer_id(); }
    SharedBuffer& shared_buffer() { return *m_buffer; }

private:
    explicit ABuffer(Vector<ASample>&& samples)
        : m_buffer(*SharedBuffer::create_with_size(samples.size() * sizeof(ASample))),
        m_sample_count(samples.size())
    {
        memcpy(m_buffer->data(), samples.data(), samples.size() * sizeof(ASample));
    }

    explicit ABuffer(NonnullRefPtr<SharedBuffer>&& buffer, int sample_count)
        : m_buffer(move(buffer)),
        m_sample_count(sample_count)
    {
    }

    NonnullRefPtr<SharedBuffer> m_buffer;
    const int m_sample_count;
};
