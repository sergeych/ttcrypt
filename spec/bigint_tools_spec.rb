require 'spec_helper'

describe 'bigint-tools' do

  it 'should conver big integer to byte array and back' do

    value = 0x111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
    value_le =0xffffeeeeddddccccbbbbaaaa999988887777666655554444333322221111
    value.to_bytes(order: :BE).bytes_to_integer.should == value

    value.to_bytes(order: :LE).bytes_to_integer.should == value_le
    value.to_bytes(order: :LE).bytes_to_integer(order: :LE).should == value
  end

end
