require 'rspec'
$: << File.join(File.dirname(__FILE__), '../../../libraries')
require 'uri'
require 'helper_hkp_fetcher'

describe BswTech::Hkp::KeyFetcher do
  before(:each) do
    @test_key_id = '561F9B9CAC40B2F7'
    @expected_key_bits = <<-EOF
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: SKS 1.1.4
Comment: Hostname: keyserver.ubuntu.com

mQINBFHQWNwBEAC/W8LzfDosK6KbEvU5Z1AiYVmKO18BZ1Umhjaz5pyUFZrPjEwKUUX4WidA
lbccl3lBx9b3sxNDGGVEdBF/E2+LykqtOgY4fi1kjEzjAirWuQc/zVKbZRuiZNHq7EQxoiXz
gmLh36BYguW3WCCNCGxhS+ESTt0ILjoTm6xALmoNRmtztC2HwgGkbFYQLvnd06ujC06qkRQQ
Xdn/rALRfZ/sGYLJPXIh/5ifs9eTs5YG8zoAHeNigl3hvJXHLEw4JEsDCGthgP5fd4G7oYgW
nZsOXw2xX2i3DPzPSRnOe8zHwks4Ozy+EVpWI3PzFyVte9v1OjeONfUr6ZgRtQRMEH7VN027
stVdnUBy9Q1/ht0g8KskNBgl96O2lQa5z1yMmI+2B29x/mexY4B/3GTPOkvQZF36PnLOovUB
rr8y4uuqs8OFsQem7Sn9guQ6ocJCfzGCCIzEQlo6tlgpZ3mw5H4Yj8CaieYIFWFl+B7HvKrt
zejUSeqGGg4H5CkKYo5MAubblmaF9VJts9vgqAMqgs4czvKhDxAGSEhIvx9OuU4Ri5N/vc4m
109cFbp3MSfzqe1m7qA5TkDr4X0zH7rp5/SgYqOMGIuaHyXf5Eb7or7C6ItqLcpkZ6WUV72a
zvjC4SHqlMe612SB/I4CVoJ4VS5UdBHs/ZJQ6unXHTHfRXFIKQARAQABtHlQaHVzaW9uIEF1
dG9tYXRlZCBTb2Z0d2FyZSBTaWduaW5nIChVc2VkIGJ5IGF1dG9tYXRlZCB0b29scyB0byBz
aWduIHNvZnR3YXJlIHBhY2thZ2VzKSA8YXV0by1zb2Z0d2FyZS1zaWduaW5nQHBodXNpb24u
bmw+iEYEExECAAYFAlHQWUgACgkQBqExCUtvQzJWeACgxaH9YNLO6x4WqITswGQgSWi/HkAA
oMotrvRoI0sirbWf6B9vriAxVP+WiQEcBBMBAgAGBQJR0Y66AAoJEAGVTDvTtDZ79C8H/2d9
lHPbZ1XJ37dtzEuYbfPZb6+c1Q3wrYOccvl/heoow3/6qT4mOhwC75iq7F5KqQV9+yIMZbN2
piRPF4eQqFlSpWO0hSv9erQxhKZdENYtP2YWsC26ML2QgJHFFy4l0XVIYtGkwU9HLAcSOQlK
epz7Isc8zwG578AU1yqaizkVlenvbjHcsNbZEk2KbuJ676NaVRD+qrw8pCIrqO2pnnVHVFbm
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
nz4UZpePdnAM
=MDba
-----END PGP PUBLIC KEY BLOCK-----
    EOF
  end

  def check_result(actual)
    expect(actual.gsub("\\n",'')).to eq(@expected_key_bits.gsub("\\n",''))
  end

  it 'correctly retrieves a key' do
    # arrange
    fetcher = BswTech::Hkp::KeyFetcher.new

    # act
    result = fetcher.fetch_key 'keyserver.ubuntu.com', @test_key_id

    # assert
    check_result result
  end

  it 'correctly retrieves a key with a full URL as the key server' do
    # arrange
    fetcher = BswTech::Hkp::KeyFetcher.new

    # act
    result = fetcher.fetch_key 'http://keyserver.ubuntu.com:11371', @test_key_id

    # assert
    check_result result
  end

  it 'complains if the key cannot be found' do
    # arrange
    fetcher = BswTech::Hkp::KeyFetcher.new

    # act
    action = lambda { fetcher.fetch_key 'keyserver.ubuntu.com', 'blah' }

    # assert
    expect(action).to raise_exception "Contacted key server OK, but key ID 'blah' was not found"
  end

  it 'complains if the key server cannot be contacted' do
    # arrange
    fetcher = BswTech::Hkp::KeyFetcher.new

    # act
    action = lambda { fetcher.fetch_key 'blah', 'key_id' }

    # assert
    expect(action).to raise_exception "Unable to contact key server 'http://blah:11371/pks/lookup?options=mr&op=get&search=0xkey_id', details: getaddrinfo: nodename nor servname provided, or not known"
  end
end