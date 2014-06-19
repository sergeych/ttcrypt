require 'spec_helper'
require 'ttcrypt'
require 'securerandom'
require 'base64'
require 'openssl'

describe 'rsa-oaep' do

  # include TTCrypt

  it 'should do factorization' do
    # p test1("hello guys")
    p1      = 0x10001
    p2      = 101
    factors = TTCrypt.factorize(p1*p2).sort
    factors[0].should == p2
    factors[1].should == p1
  end

  it 'should generate keys in background' do
    stopme  = false
    counter = 0
    Thread.start {
      while !stopme
        counter += 1
        sleep(0.001)
      end
    }
    rsa    = TTCrypt::RsaKey.generate 1024
    stopme = true
    counter.should > 0
    rsa.bits.should == 1024
  end

  it 'should not encrypt without key' do
    key = TTCrypt::RsaKey.new
    -> { key.decrypt('bad idea') }.should raise_error(TTCrypt::RsaKey::Error)
  end


  context 'having key' do
    before :all do
      @key = TTCrypt::RsaKey.generate 1024
    end

    it 'should round trip generated keys' do
      msg = 'hello, world'
      (decrypted=@key.decrypt((encrypted=@key.encrypt(msg)))).should == msg
      encrypted.encoding.should == Encoding::BINARY
      decrypted.encoding.should == Encoding::BINARY

      -> { @key.encrypt 'way too long message to encrypt it!!!!!!!'*12 }
      .should raise_error(TTCrypt::RsaKey::Error)

    end

    it 'should round trip signatures' do
      message = 'che bella cosa'
      %i|sha1 sha256|.each { |hash_name|
        signature = @key.sign(message, hash_name)
        signature.length.should == 128
        signature.encoding.should == Encoding::BINARY
        @key.verify(message, signature, hash_name).should be_true
        @key.verify(message+'...', signature, hash_name).should be_false
        bad_signature = signature.clone
        bad_signature.setbyte(0, bad_signature.getbyte(0) ^ 11)
        @key.verify(message, bad_signature, hash_name).should be_false
        @key.verify(message, signature, hash_name).should be_true
      }
      -> { @key.sign(message, :wrong_hash) }.should raise_error
      -> { @key.verify(message, 'no matter', :wrong_hash) }.should raise_error
    end

    it 'should extract public key' do
      message = 'check key pair'
      pubkey  = @key.extract_public
      pubkey.should_not be_private
      @key.should be_private
      @key.decrypt(pubkey.encrypt(message)).should == message
    end

    it 'should provide components' do
      %i|p q e n|.each { |name|
        (val=@key.send(name)).should_not be_nil
        val.encoding.should == Encoding::BINARY
      }
      pubkey = @key.extract_public
      pubkey.p.should be_nil
      pubkey.q.should be_nil
      pubkey.e.should == @key.e
      pubkey.n.should == @key.n
    end
  end

  it 'should construct from components' do
    init_test_vectors1
    key = TTCrypt::RsaKey.new e: @e, p: @p, q: @q
    key.p.should == @p
    key.q.should == @q
    key.e.should == @e
    key.should be_private
    key.n.should_not be_nil
    key.decrypt(@encrypted_m).should == @message
    key.decrypt(key.extract_public.encrypt(@message)).should == @message
  end

  def init_test_vectors1
    @n = h2s <<-End
          bb f8 2f 09 06 82 ce 9c 23 38 ac 2b 9d a8 71 f7 36 8d 07 ee d4 10 43 a4
          40 d6 b6 f0 74 54 f5 1f b8 df ba af 03 5c 02 ab 61 ea 48 ce eb 6f cd 48
          76 ed 52 0d 60 e1 ec 46 19 71 9d 8a 5b 8b 80 7f af b8 e0 a3 df c7 37 72
          3e e6 b4 b7 d9 3a 25 84 ee 6a 64 9d 06 09 53 74 88 34 b2 45 45 98 39 4e
          e0 aa b1 2d 7b 61 a5 1f 52 7a 9a 41 f6 c1 68 7f e2 53 72 98 ca 2a 8f 59
          46 f8 e5 fd 09 1d bd cb
    End

    @e = "\x11"

    @p = h2s <<-End
          ee cf ae 81 b1 b9 b3 c9 08 81 0b 10 a1 b5 60 01 99 eb 9f 44 ae f4 fd a4
          93 b8 1a 9e 3d 84 f6 32 12 4e f0 23 6e 5d 1e 3b 7e 28 fa e7 aa 04 0a 2d
          5b 25 21 76 45 9d 1f 39 75 41 ba 2a 58 fb 65 99
    End

    @q = h2s <<-End
          c9 7f b1 f0 27 f4 53 f6 34 12 33 ea aa d1 d9 35 3f 6c 42 d0 88 66 b1 d0
          5a 0f 20 35 02 8b 9d 86 98 40 b4 16 66 b4 2e 92 ea 0d a3 b4 32 04 b5 cf
          ce 33 52 52 4d 04 16 a5 a4 41 e7 00 af 46 15 03
    End

    @message = h2s 'd4 36 e9 95 69 fd 32 a7 c8 a0 5b bc 90 d3 2c 49'

    @encrypted_m = h2s <<-End
          12 53 e0 4d c0 a5 39 7b b4 4a 7a b8 7e 9b f2 a0 39 a3 3d 1e 99 6f c8 2a 94
          cc d3 00 74 c9 5d f7 63 72 20 17 06 9e 52 68 da 5d 1c 0b 4f 87 2c f6 53 c1
          1d f8 23 14 a6 79 68 df ea e2 8d ef 04 bb 6d 84 b1 c3 1d 65 4a 19 70 e5 78
          3b d6 eb 96 a0 24 c2 ca 2f 4a 90 fe 9f 2e f5 c9 c1 40 e5 bb 48 da 95 36 ad
          87 00 c8 4f c9 13 0a de a7 4e 55 8d 51 a7 4d df 85 d8 b5 0d e9 68 38 d6 06
          3e 09 55
    End
  end

  def h2s hex
    hex = hex.gsub(/\s+/, '')
    hex.chars.each_slice(2).map{|x,y| (x.to_i(16)<<4 | y.to_i(16)).chr}.join
  end


#   include Ttcrypt::NumUtils
#
#   before :all do
#     # test vectors
#     init_test_vectors
#   end
#
#   it 'should convert long to bytes and back' do
#     30.times {
#       n     = SecureRandom.random_number (17+SecureRandom.random_number(157))
#       k     = SecureRandom.random_number(5) + 2
#       bytes = long_to_bytes n, k
#       (bytes.length % k).should == 0
#       bytes_to_long(bytes).should == n
#     }
#
#     src = "\x00\v\x9DtX\xA2\xAB\xAF%\xD4\xE9Xz\x9F\x9C\xC4\b\r\xDE\x14\xD8\x17\x01\xE1\x04\x04\x92\x16\xCD\x1D\x17+\xB1\xA0&6\xF9'\x8FsK\x95\xCC\x161\xAD3\xBB\x8F\xBE\x11\xBDP\xE4Z\x8E\x8Cz\xD7\x95\xC8\xA5(\x8E"
#     long_to_bytes(bytes_to_long(src), src.length).should == src
#
#     long_to_bytes(0, 5).should == "\x00\x00\x00\x00\x00".force_encoding(Encoding::BINARY)
#     long_to_bytes(1, 2).should == "\x00\x01".force_encoding(Encoding::BINARY)
#   end
#
#   it 'it should run gmp' do
#     a  = GMP.Z((_a=11098707803864973769487639874))
#     b  = GMP.Z((_b=23456))
#     c  = GMP.Z((_c=803947509837450987038475))
#     r  = a.powmod(b, c)
#     r1 = (_a ** _b) % _c
#     r.should == r1
#   end
#
#   it 'should properly pad' do
#     k = (bitlength(@n)+7)/8
#     Ttcrypt::RsaKey.set_debug_oaep_seed @seed
#     p k
#     res = Ttcrypt::RsaKey.eme_oaep_encode(long_to_bytes(@message), k-1)
#     bytes_to_long(res).should == @em
#   end
#
#   it 'should properly depad' do
#     src = Ttcrypt::RsaKey.eme_oaep_decode long_to_bytes(@em)
#     bytes_to_long(src).should == @message
#   end
#
#   it 'should properly public encrypt' do
#     em = test_key.public_encrypt long_to_bytes(@message)
#     bytes_to_long(em).should == @encrypted_m
#   end
#
#   it 'should properly private decrypt' do
#     m = test_key(restrict: true).private_decrypt long_to_bytes(@encrypted_m)
#     bytes_to_long(m).should == @message
#     m = test_key.private_decrypt long_to_bytes(@encrypted_m)
#     bytes_to_long(m).should == @message
#
#     # a = 123101010122
#     # b = 778901
#     # puts "Inverse #{a}, #{b}-> #{inverse(a,b)}"
#
#     puts "Sha1 empty "+Digest::SHA1.digest('').to_hex
#     puts "Sha1 sergeych forever "+Digest::SHA1.digest('sergeych forever').to_hex
#   end
#
#   it 'should properly private encrypt and public decrypt'
#
#   it 'should generate keys'
#
#   it 'should construct crypstie keys'
#   it 'should serialize crypstie keys'
#
#   def h2s hex_string
#     hex_string.gsub(/\s+/, '').to_i(16)
#   end
#
#   def test_key restrict: false
#     Ttcrypt::RsaKey.set_debug_oaep_seed @seed
#     if restrict
#       Ttcrypt::RsaKey.new n: @n, e: @e, d: inverse(@e, lcm(@p - 1, @q - 1))
#     else
#       Ttcrypt::RsaKey.new n: @n, e: @e, p: @p, q: @q
#     end
#   end
#
#   def init_test_vectors
#     @n = h2s <<-End
#       bb f8 2f 09 06 82 ce 9c 23 38 ac 2b 9d a8 71 f7 36 8d 07 ee d4 10 43 a4
#       40 d6 b6 f0 74 54 f5 1f b8 df ba af 03 5c 02 ab 61 ea 48 ce eb 6f cd 48
#       76 ed 52 0d 60 e1 ec 46 19 71 9d 8a 5b 8b 80 7f af b8 e0 a3 df c7 37 72
#       3e e6 b4 b7 d9 3a 25 84 ee 6a 64 9d 06 09 53 74 88 34 b2 45 45 98 39 4e
#       e0 aa b1 2d 7b 61 a5 1f 52 7a 9a 41 f6 c1 68 7f e2 53 72 98 ca 2a 8f 59
#       46 f8 e5 fd 09 1d bd cb
#     End
#
#     @e = 0x11
#
#     @p = h2s <<-End
#       ee cf ae 81 b1 b9 b3 c9 08 81 0b 10 a1 b5 60 01 99 eb 9f 44 ae f4 fd a4
#       93 b8 1a 9e 3d 84 f6 32 12 4e f0 23 6e 5d 1e 3b 7e 28 fa e7 aa 04 0a 2d
#       5b 25 21 76 45 9d 1f 39 75 41 ba 2a 58 fb 65 99
#     End
#
#     @q = h2s <<-End
#       c9 7f b1 f0 27 f4 53 f6 34 12 33 ea aa d1 d9 35 3f 6c 42 d0 88 66 b1 d0
#       5a 0f 20 35 02 8b 9d 86 98 40 b4 16 66 b4 2e 92 ea 0d a3 b4 32 04 b5 cf
#       ce 33 52 52 4d 04 16 a5 a4 41 e7 00 af 46 15 03
#     End
#
#     @dP = h2s <<-End
#       54 49 4c a6 3e ba 03 37 e4 e2 40 23 fc d6 9a 5a eb 07 dd dc 01 83 a4 d0
#       ac 9b 54 b0 51 f2 b1 3e d9 49 09 75 ea b7 74 14 ff 59 c1 f7 69 2e 9a 2e
#       20 2b 38 fc 91 0a 47 41 74 ad c9 3c 1f 67 c9 81
#     End
#
#     @dQ = h2s <<-End
#       47 1e 02 90 ff 0a f0 75 03 51 b7 f8 78 86 4c a9 61 ad bd 3a 8a 7e 99 1c
#       5c 05 56 a9 4c 31 46 a7 f9 80 3f 8f 6f 8a e3 42 e9 31 fd 8a e4 7a 22 0d
#       1b 99 a4 95 84 98 07 fe 39 f9 24 5a 98 36 da 3d
#     End
#
#     @qInv = h2s <<-End
#       b0 6c 4f da bb 63 01 19 8d 26 5b db ae 94 23 b3 80 f2 71 f7 34 53 88 50
#       93 07 7f cd 39 e2 11 9f c9 86 32 15 4f 58 83 b1 67 a9 67 bf 40 2b 4e 9e
#       2e 0f 96 56 e6 98 ea 36 66 ed fb 25 79 80 39 f7
#     End
#
#     @message = h2s 'd4 36 e9 95 69 fd 32 a7 c8 a0 5b bc 90 d3 2c 49'
#
#     @pHash = h2s 'da 39 a3 ee 5e 6b 4b 0d 32 55 bf ef 95 60 18 90 af d8 07 09'
#
#     @seed = h2s 'aa fd 12 f6 59 ca e6 34 89 b4 79 e5 07 6d de c2 f0 6c b5 8f'
#
#     @em = h2s <<-End
#       eb 7a 19 ac e9 e3 00 63 50 e3 29 50 4b 45 e2 ca 82 31 0b 26 dc d8 7d 5c 68
#       f1 ee a8 f5 52 67 c3 1b 2e 8b b4 25 1f 84 d7 e0 b2 c0 46 26 f5 af f9 3e dc
#       fb 25 c9 c2 b3 ff 8a e1 0e 83 9a 2d db 4c dc fe 4f f4 77 28 b4 a1 b7 c1 36
#       2b aa d2 9a b4 8d 28 69 d5 02 41 21 43 58 11 59 1b e3 92 f9 82 fb 3e 87 d0
#       95 ae b4 04 48 db 97 2f 3a c1 4f 7b c2 75 19 52 81 ce 32 d2 f1 b7 6d 4d 35
#       3e 2d
#     End
#
#     @encrypted_m = h2s <<-End
#       12 53 e0 4d c0 a5 39 7b b4 4a 7a b8 7e 9b f2 a0 39 a3 3d 1e 99 6f c8 2a 94
#       cc d3 00 74 c9 5d f7 63 72 20 17 06 9e 52 68 da 5d 1c 0b 4f 87 2c f6 53 c1
#       1d f8 23 14 a6 79 68 df ea e2 8d ef 04 bb 6d 84 b1 c3 1d 65 4a 19 70 e5 78
#       3b d6 eb 96 a0 24 c2 ca 2f 4a 90 fe 9f 2e f5 c9 c1 40 e5 bb 48 da 95 36 ad
#       87 00 c8 4f c9 13 0a de a7 4e 55 8d 51 a7 4d df 85 d8 b5 0d e9 68 38 d6 06
#       3e 09 55
#     End
#   end
#
end
#
# class String
#   def to_hex
#     n   = 0
#     res = ''
#     each_byte { |b|
#       res << ('%02x ' % b)
#       res += "\n" if (n += 1) % 24 == 0
#     }
#     res
#   end
# end
#
#
