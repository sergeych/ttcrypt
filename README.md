# TTCrypt

Attention: this version is yet not fully functional.

TTCrypt is a fast basic cryptography library written in C++ that implements only string encoded RSA 
variants and othe cryptoprimitives widely used in Thrift projects, namely:

* RSAES-OAEP encryption
* RSASS-PSS signing
* Pollard 'rho' factorization
* SHA1 and SHA256 hashes (under development)
* RJ256/256 (under development)

## Installation

Current implementation targeted fro MRI ruby 2.0+.

To install your computer should have GMP library installed. Use your target system's packet manager
(apt, brew, whatever you have) or get it there: https://gmplib.org

Then, add this line to your application's Gemfile:

    gem 'ttcrypt'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install ttcrypt

## Usage

So far you can use rdoc.

TODO: Write usage instructions here

## Contributing

1. Fork it ( https://github.com/[my-github-username]/ttcrypt/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
