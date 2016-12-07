# TTCrypt

TTCrypt is a fast basic cryptography library written in C++ that implements only string encoded RSA 
variants and othe cryptoprimitives widely used in Thrift/iCodici projects, namely:

* RSAES-OAEP encryption
* RSASS-PSS signing (sha1, sha256 and sha512 are supported)
* Pollard 'rho' factorization
* Fast orime generation
* SHA1, SHA256 and SHA512 hashes

All long operation are being preformed releasing GVL so other ruby threads can execute while ttcrypt
thinks.

## Changes

After years in production we are added SHA512 signing hash and ability to caclulate hashes for strings - it's faster than using Digest module - at least on reasonable sized sources we use.

## Installation

Current implementation targeted for MRI ruby 2.0+.

To install your computer should have GMP library installed. Use your target system's packet manager
(apt, brew, whatever you have) or get it there: https://gmplib.org

Then, add this line to your application's Gemfile:

    gem 'ttcrypt'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install ttcrypt

## Usage

Very simple, for example:

```ruby
    private_key = TTCrypt::RsaKey.generate 2048
    public_key = private_key.extract_public
    
    ciphered = public_key.encrypt 'some message'
    decrypted = private_key.decrypt ciphered
    
    signature = private_key.sign 'some message to sign', :sha256
    is_ok = public_key.verify 'some message to sign', signature, :sha256
```
    

See [online docs](http://www.rubydoc.info/gems/ttcrypt) for more information.

## Contributing

1. Fork it ( https://github.com/[my-github-username]/ttcrypt/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
