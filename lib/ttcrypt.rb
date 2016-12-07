# Thrift cryptographics primitives: fast c++ implementation, only strong schemes,
# releases GVL on long operations so other threads can be executed in parallel.


class Numeric

  # Convert an integer non-negative number that to bytes array using specified endianness. if it is
  # float, it will be converted to an integer first.
  #
  # @return [Symbol] either :BE or :LE
  def to_bytes order: :BE
    order == :BE || order == :LE or raise ArgimentError, "unkown order, should be either :BE or :LE"
    (value  = self.to_i) < 0 and raise ArgumentError, 'value must not be negative'
    result = ''
    result.force_encoding 'binary'
    while value != 0
      byte  = value & 0xFF
      value >>= 8
      result << byte.chr
    end
    result == '' ? "\x0" : (order == :BE ? result.reverse : result)
  end

end

class String

  # Convert string that is supposed to be binary data to integer value
  # using specified bytes order
  # @return [Symbol] either :BE or :LE
  def bytes_to_integer order: :BE
    order == :BE || order == :LE or raise ArgimentError, "unkown order, should be either :BE or :LE"
    result = 0
    (order == :BE ? self.bytes : self.bytes.reverse).each { |b|
      result = (result << 8) | b.ord
    }
    result
  end
end

module TTCrypt

  # Pollard 'rho' prime factorization. Allows execution of other ruby
  # threads in parallel (releases GVL)
  #
  # @return [int] array of prime factors
  def factorize composite
    _factorize2(composite.to_bytes).map { |f| f.bytes_to_integer }
    # hex = composite.to_i.to_s(16)
    # hex = '0' + hex if (hex.length & 1) == 1
    # _factorize(hex).map { |x| x.to_i(16) }
  end

  # Generate random probable prime number with a given bits length. This implementation will generate
  # prime such as 2^(bits-1) < prime < 2 ^ bits.
  #
  def generate_prime bits
    _generate_prime(bits).to_i(16)
  end

  # Generate fast SHA512 hash of a source string and return it in the binary form
  #
  # @param [String] source binary string
  # @return [String] binary string with calculated hash code
  def sha512(source)
    # stub for documentation, real finction is in the native code
  end

  # Generate fast SHA256 hash of a source string and return it in the binary form
  #
  # @param [String] source binary string
  # @return [String] binary string with calculated hash code
  def sha256(source)
    # stub for documentation, real finction is in the native code
  end

  # Implementation of RSAES-OAEP encryption and RSASSA-PSS signing
  # accroding to pkcs#1 v2.2 specification. Does NOT implement any previous cryptographically
  # weak shcemes (like 1.5 signature) - go use openssl for itm but it does compromise private
  # key.
  #
  # All time consuming operations are executed releasing GVL so other threads can run in parallel
  # in the multicore hardware.
  #
  class RsaKey

    # raised when some parameters of RSAES are invalid, e.g.
    # message/representation is too long, encrypted message or representation
    # is not properly padded
    class Error < StandardError
    end

    ACCEPTED_PARAMS = %i|n e p q d|

    def initialize ** params
      set_params(params)
    end

    def set_params ** params
      res = {}
      params.each { |k, v|
        ACCEPTED_PARAMS.include?(k) or raise ArgumentError, "unknown key component"
        res[k.to_s] = v.to_s.force_encoding(Encoding::BINARY)
      }
      _set_params res
    end

    # Generate private key (that contains public key too) of the desired bit
    # length (recommended at least 2048).
    def self.generate bits_strength
      k = RsaKey.new
      k._generate(bits_strength)
    end

    # Get key size in bits
    def bits
      _bits
    end

    # Encrypt message with public key using RSAES-OAEP scheme
    # (pkcs#1 v.2.2).
    def encrypt message
      message.force_encoding Encoding::BINARY
      _encrypt message
    end

    # Decrypt message with private key using RSAES-OAEP scheme
    # (pkcs#1 v.2.2). Requires private key
    #
    def decrypt message
      message.force_encoding Encoding::BINARY
      _decrypt message
    end

    # Sign the message using pkcs#1 v2.2 RSASSA-PSS
    # process. Requires private key.
    #
    #@param [String] message to sign
    #@param [Symbol|String] hash function used (:sha1 or :sha256)
    #@return [bool] true if the signature is consistent
    def sign message, hash_name
      message.force_encoding Encoding::BINARY
      _sign message, hash_name.to_s.downcase
    end
    
    # Check message signature signed with pkcs#1 v2.2 RSASSA-PSS
    # process
    #
    #@param [String] message to verify
    #@param [String] signature
    #@param [Symbol|String] hash function used (:sha1 or :sha256)
    #@return [bool] true if the signature is consistent
    def verify message, signature, hash_name=:sha1
      message.force_encoding Encoding::BINARY
      signature.force_encoding Encoding::BINARY
      _verify message, signature, hash_name.to_s.downcase
    end

    # Extract public key from a private (or public) key
    # @return [RsaKey] public key instance
    def extract_public
      # native implementation: this is for indexing only
    end

    # true if self contains private key
    def private?
      _is_private
    end

    # Get key components as hash. Components are binary strings, indexes are symbols
    # e.g. :n, :e
    def components
      @components ||= _components
    end

    # @return [String] P component or nil
    def p
      components[:p]
    end

    def q
      components[:q]
    end

    def n
      components[:n]
    end

    def e
      components[:e]
    end

  end
end

# it should require native lib after module definition above
# otherwise won't work!
require 'ttcrypt/ttcrypt'

module TTCrypt
  module_function :factorize, :_factorize, :_factorize2, :generate_prime, :_generate_prime, :sha256, :sha512
end

