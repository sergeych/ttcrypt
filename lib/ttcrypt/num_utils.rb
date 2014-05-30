#
# Some integer math utilities commonly used in cryptography
#

module TTcrypt
  module NumUtils

    ZERO_CHAR = "\x00".force_encoding(Encoding::BINARY)
    ONE_CHAR  = "\x01".force_encoding(Encoding::BINARY)

    # Convert unsigned long integer into bytes big-endian string
    #
    # @param [Object] n number to convert to bytes
    # @param [Integer] block_size if present, then the block will be filled with lead
    #                  zeroes (if need) so that the length is multiple of block_size
    def long_to_bytes n, block_size=0
      n = n.to_i
      buffer = ''.force_encoding(Encoding::BINARY)
      while n > 0
        buffer = [n & 0xFFFFffff].pack('L>') + buffer
        n      >>= 32
      end

      i=0
      i += 1 while buffer[i] == ZERO_CHAR

      buffer = i < buffer.length ? buffer[i..-1] : ZERO_CHAR

      if block_size > 0 && (buffer.length % block_size) > 0
        buffer = ZERO_CHAR * (block_size - buffer.length % block_size) + buffer
      end
      buffer
    end

    # Convert big-endian bytes string back to unsigned long integer. Reverse of
    # long_to_bytes.
    # @param [String] bytes binary encoded string
    def bytes_to_long bytes
      bytes.force_encoding Encoding::BINARY
      acc    = 0
      length = bytes.length
      if (r = length % 4) != 0
        extra = 4 - r
        bytes = ZERO_CHAR * extra + bytes
      end

      (0...length).step(4) { |i|
        acc = (acc << 32) + bytes[i...i+4].unpack('L>')[0]
      }
      GMP.Z(acc)
    end

    # Calculate Greatest Common Divisor of x,y
    #
    # @param [Integer] x
    # @param [Integer] y
    def gcd x, y
      x, y = x.abs, y.abs
      while x > 0
        x, y = y % x, x
      end
      y
    end

    # Return Least Common Multiplier for a, b
    #
    # @param [Integer] b
    # @param [Integer] a
    def lcm a, b
      a, b = a.to_i, b.to_i
      a * b / gcd(a, b)
    end

    # Inverse of (u mod v), see http://en.wikipedia.org/wiki/Modular_multiplicative_inverse
    def inverse u, v
      u, v = u.to_i, v.to_i
      u3, v3 = u, v
      u1, v1 = 1, 0
      while v3 > 0
        q      = u3 / v3
        u1, v1 = v1, u1 - v1 * q
        u3, v3 = v3, u3 - v3 * q
      end
      while u1 < 0
        u1 += v
      end
      u1
    end

    # @return number of bits in the specified value
    def bitlength val
      return 1 if val == 0
      bits = 0
      while val != 0
        val  >>= 1
        bits += 1
      end
      bits
    end

    # @return [String] xor a and b. should have same size
    def xor a, b
      a.length == b.length or raise ArgumentError, 'size mismatch'
      a.bytes.zip(b.bytes).map { |x, y| (x ^ y).chr }.join
    end


    module_function :bytes_to_long

  end
end

