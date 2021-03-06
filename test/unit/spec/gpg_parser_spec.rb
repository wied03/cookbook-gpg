require 'rspec'
$: << File.join(File.dirname(__FILE__), '../../..')
require 'libraries/helper_key_header'
require 'libraries/helper_gpg_parser'

describe BswTech::Gpg::GpgParser do
  it 'parses no keys properly' do
    # arrange
    gpg_output = ''

    # act
    result = BswTech::Gpg::GpgParser.new.parse_output_ring gpg_output

    # assert
    expect(result).to eq []
  end

  it 'parses a 1 ring secret key' do
    # arrange
    gpg_output = <<-EOF
sec::2048:1:318012D61E7D2809:1402513817:1528657817:::::::::
fpr:::::::::FEF5267480835871C5EC3382318012D61E7D2809:
uid:::::::1EA38BE523ED83582ACF18DA1F71C7121673FE58::Brady Wied <brady@bswtechconsulting.com>:
ssb::2048:1:3409D865DF94190A:1402513817::::::::::
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse_output_ring gpg_output

    # assert
    result.should have(1).items
    key = result[0]
    key.fingerprint.should == 'FEF5267480835871C5EC3382318012D61E7D2809'
    key.usernames.should == 'Brady Wied <brady@bswtechconsulting.com>'
    key.id.should == '1E7D2809'
    key.type.should == :secret_key
  end

  it 'parses multiple ring secret keys' do
    # arrange
    gpg_output = <<-EOF
sec::2048:1:318012D61E7D2809:1402513817:1528657817:::::::::
fpr:::::::::FEF5267480835871C5EC3382318012D61E7D2809:
uid:::::::1EA38BE523ED83582ACF18DA1F71C7121673FE58::Brady Wied <brady@bswtechconsulting.com>:
ssb::2048:1:3409D865DF94190A:1402513817::::::::::
sec::2048:1:7E75A58532E18F7B:1408315896:1471387896:::::::::
fpr:::::::::A7A5347B5F4AD499E7D1318E7E75A58532E18F7B:
uid:::::::121D20F8264B5BF08BE5EA3CDC213B5ED2FA1632::Brady Test 2 (foo) <bt@wied.us>:
ssb::2048:1:D1D60030A73B82AE:1408315896::::::::::

    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse_output_ring gpg_output

    # assert
    result.should have(2).items
    key = result[0]
    key.fingerprint.should == 'FEF5267480835871C5EC3382318012D61E7D2809'
    key.usernames.should == 'Brady Wied <brady@bswtechconsulting.com>'
    key.id.should == '1E7D2809'
    key.type.should == :secret_key
    key = result[1]
    key.fingerprint.should == 'A7A5347B5F4AD499E7D1318E7E75A58532E18F7B'
    key.usernames.should == 'Brady Test 2 (foo) <bt@wied.us>'
    key.id.should == '32E18F7B'
    key.type.should == :secret_key
  end

  it 'parses 1 ring public key' do
    # arrange
    gpg_output = <<-EOF
tru::1:1408259102:1471331046:3:1:5
pub:u:2048:1:4463F8F9CA62B81E:1408259046:1471331046::u:::escaESCA:
fpr:::::::::A6BB3E7C28480ADBC59864CF4463F8F9CA62B81E:
uid:u::::1408259046::6E21306159AB51C0B6D371108CEBC40314F17526::pkg_key dev <dev@aptly.bswtechconsulting.com>:
sub:u:2048:1:05D96AC415DB901E:1408259046:1471331046:::::esa:
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse_output_ring gpg_output

    # assert
    result.should have(1).items
    key = result[0]
    key.fingerprint.should == 'A6BB3E7C28480ADBC59864CF4463F8F9CA62B81E'
    key.usernames.should == 'pkg_key dev <dev@aptly.bswtechconsulting.com>'
    key.id.should == 'CA62B81E'
    key.type.should == :public_key
  end

  it 'deals with escaped colons properly' do
    # arrange
    gpg_output = <<-EOF
tru::1:1408259102:1471331046:3:1:5
pub:u:2048:1:4463F8F9CA62B81E:1408259046:1471331046::u:::escaESCA:
fpr:::::::::A6BB3E7C28480ADBC59864CF4463F8F9CA62B81E:
uid:u::::1408259046::6E21306159AB51C0B6D371108CEBC40314F17526::pkg_key dev (something\\x3a good) <dev@aptly.bswtechconsulting.com>:
sub:u:2048:1:05D96AC415DB901E:1408259046:1471331046:::::esa:
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse_output_ring gpg_output

    # assert
    result.should have(1).items
    key = result[0]
    key.fingerprint.should == 'A6BB3E7C28480ADBC59864CF4463F8F9CA62B81E'
    key.usernames.should == 'pkg_key dev (something: good) <dev@aptly.bswtechconsulting.com>'
    key.id.should == 'CA62B81E'
    key.type.should == :public_key
  end

  it 'parses properly with no ring keys there' do
    # arrange
    gpg_output = ''

    # act
    result = BswTech::Gpg::GpgParser.new.parse_output_ring gpg_output

    # assert
    result.should have(0).items
  end

  it 'parses properly with multiple public ring keys there' do
    # arrange
    gpg_output = <<-EOF
tru::1:1408316224:1471387896:3:1:5
pub:u:2048:1:318012D61E7D2809:1402513817:1528657817::u:::scESC:
fpr:::::::::FEF5267480835871C5EC3382318012D61E7D2809:
uid:u::::1402513817::1EA38BE523ED83582ACF18DA1F71C7121673FE58::Brady Wied <brady@bswtechconsulting.com>:
sub:u:2048:1:3409D865DF94190A:1402513817:1528657817:::::e:
pub:f:4096:1:DF4FD2ABB22D2CD5:1397276517:::-:::escaESCA:
fpr:::::::::D8184DB03ECA8237A1DA9033DF4FD2ABB22D2CD5:
uid:f::::1397276517::6C4FE5065C9D1B65FFF2721428E7DFB7CAE41387::keybase.io/leolaporte <leolaporte@keybase.io>:
uat:f::::1397277811::215F133D4F87733658BDBDDA99157905F6DE2510::1 15274:
sub:f:2048:1:44E11D40E0A7E424:1397276517:1649564517:::::esa:
pub:u:2048:1:7E75A58532E18F7B:1408315896:1471387896::u:::scESC:
fpr:::::::::A7A5347B5F4AD499E7D1318E7E75A58532E18F7B:
uid:u::::1408315896::121D20F8264B5BF08BE5EA3CDC213B5ED2FA1632::Brady Test 2 (foo) <bt@wied.us>:
sub:u:2048:1:D1D60030A73B82AE:1408315896:1471387896:::::e:
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse_output_ring gpg_output

    # assert
    result.should have(3).items
    key = result[0]
    key.fingerprint.should == 'FEF5267480835871C5EC3382318012D61E7D2809'
    key.usernames.should == 'Brady Wied <brady@bswtechconsulting.com>'
    key.id.should == '1E7D2809'
    key.type.should == :public_key
    key = result[1]
    key.fingerprint.should == 'D8184DB03ECA8237A1DA9033DF4FD2ABB22D2CD5'
    key.usernames.should == 'keybase.io/leolaporte <leolaporte@keybase.io>'
    key.id.should == 'B22D2CD5'
    key.type.should == :public_key
    key = result[2]
    key.fingerprint.should == 'A7A5347B5F4AD499E7D1318E7E75A58532E18F7B'
    key.usernames.should == 'Brady Test 2 (foo) <bt@wied.us>'
    key.id.should == '32E18F7B'
    key.type.should == :public_key
  end

  it 'parses 1 secret external key OK' do
    # arrange
    gpg_output = <<-EOF
sec::2048:1:4463F8F9CA62B81E:1408259046:1471331046:::pkg_key dev <dev@aptly.bswtechconsulting.com>:
fpr:::::::::A6BB3E7C28480ADBC59864CF4463F8F9CA62B81E:
ssb::2048:1:05D96AC415DB901E:1408259046::::
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse_output_external gpg_output

    # assert
    result.should have(1).items
    key = result[0]
    key.fingerprint.should == 'A6BB3E7C28480ADBC59864CF4463F8F9CA62B81E'
    key.usernames.should == 'pkg_key dev <dev@aptly.bswtechconsulting.com>'
    key.id.should == 'CA62B81E'
    key.type.should == :secret_key
  end

  it 'parses a new header OK' do
    # arrange
    gpg_output = <<-EOF
pub:-:4096:1:561F9B9CAC40B2F7:1372608732:::-:
fpr:::::::::16378A33A6EF16762922526E561F9B9CAC40B2F7:
uid:::::::::Phusion Automated Software Signing (Used by automated tools to sign software packages) <auto-software-signing@phusion.nl>:
sub:-:4096:1:CF693C004DB76CB6:1372608732::::
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse_output_external gpg_output

    # assert
    result.should have(1).items
    key = result[0]
    key.fingerprint.should == '16378A33A6EF16762922526E561F9B9CAC40B2F7'
    key.usernames.should == 'Phusion Automated Software Signing (Used by automated tools to sign software packages) <auto-software-signing@phusion.nl>'
    key.id.should == 'AC40B2F7'
    key.type.should == :public_key
  end

  it 'parses 1 public external key OK' do
    # arrange
    gpg_output = <<-EOF
pub:-:2048:1:4463F8F9CA62B81E:1408259046:1471331046::-:pkg_key dev <dev@aptly.bswtechconsulting.com>:
fpr:::::::::A6BB3E7C28480ADBC59864CF4463F8F9CA62B81E:
sub:-:2048:1:05D96AC415DB901E:1408259046:1471331046::: [expires: 2016-08-16]
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse_output_external gpg_output

    # assert
    result.should have(1).items
    key = result[0]
    key.fingerprint.should == 'A6BB3E7C28480ADBC59864CF4463F8F9CA62B81E'
    key.usernames.should == 'pkg_key dev <dev@aptly.bswtechconsulting.com>'
    key.id.should == 'CA62B81E'
    key.type.should == :public_key
  end

  it 'gives an error if an unexpected key type is encountered when parsing external key stuff' do
    # arrange
    gpg_output = <<-EOF
bla:-:2048:1:4463F8F9CA62B81E:1408259046:1471331046::-:pkg_key dev <dev@aptly.bswtechconsulting.com>:
fpr:::::::::A6BB3E7C28480ADBC59864CF4463F8F9CA62B81E:
sub:-:2048:1:05D96AC415DB901E:1408259046:1471331046::: [expires: 2016-08-16]
    EOF

    # act
    action = lambda { BswTech::Gpg::GpgParser.new.parse_output_external gpg_output }

    # assert
    expect(action).to raise_exception /Unable to find public or secret key in records.*/
  end

  it 'parses an external public key with multiple usernames' do
    # arrange
    gpg_output = <<-EOF
tru::1:1411066794:1474138748:3:1:5
pub:u:2048:1:2DBE22CE37B8619D:1411066748:1474138748::u:::scESC:
fpr:::::::::36F99E5103F443E6C3B0C7FA2DBE22CE37B8619D:
uid:u::::1411066777::B32D279CBB4B9ABF26BE2CC705D8780D572FC13E::John Doe <john2@doe2.com>:
uid:u::::1411066748::22DFC50E5CED717233C90C47C03E044A7EA483DC::John Doe <john@doe.com>:
sub:u:2048:1:1BA7B926508C1AF7:1411066748:1474138748:::::e:
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse_output_external gpg_output

    # assert
    result.should have(1).items
    key = result[0]
    expect(key.fingerprint).to eq '36F99E5103F443E6C3B0C7FA2DBE22CE37B8619D'
    expect(key.usernames.sort).to eq ['John Doe <john2@doe2.com>',
                                      'John Doe <john@doe.com>']
    expect(key.id).to eq '37B8619D'
    expect(key.type).to eq :public_key
  end

  it 'parses an external secret key with multiple usernames' do
    # arrange
    gpg_output = <<-EOF
sec::2048:1:2DBE22CE37B8619D:1411066748:1474138748:::::::::
fpr:::::::::36F99E5103F443E6C3B0C7FA2DBE22CE37B8619D:
uid:::::::22DFC50E5CED717233C90C47C03E044A7EA483DC::John Doe <john@doe.com>:
uid:::::::B32D279CBB4B9ABF26BE2CC705D8780D572FC13E::John Doe <john2@doe2.com>:
ssb::2048:1:1BA7B926508C1AF7:1411066748::::::::::
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse_output_external gpg_output

    # assert
    result.should have(1).items
    key = result[0]
    expect(key.fingerprint).to eq '36F99E5103F443E6C3B0C7FA2DBE22CE37B8619D'
    expect(key.usernames.sort).to eq ['John Doe <john2@doe2.com>',
                                      'John Doe <john@doe.com>']
    expect(key.id).to eq '37B8619D'
    expect(key.type).to eq :secret_key
  end

  it 'parses an external public key with multiple usernames in gpg 2.0.22 format' do
    # arrange
    gpg_output = <<-EOF
pub:-:2048:1:E2165290F291A664:1411070340:1474142340::-:John Doe <john@doe.com>:
fpr:::::::::85F100D09E9DFF4353DF461CE2165290F291A664:
uid:::::::::John Doe <john2@doe2.com>:
sub:-:2048:1:9CB992C6F1BDD31A:1411070340:1474142340::: [expires: 2016-09-17]
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse_output_external gpg_output

    # assert
    result.should have(1).items
    key = result[0]
    expect(key.fingerprint).to eq '85F100D09E9DFF4353DF461CE2165290F291A664'
    expect([*key.usernames].sort).to eq ['John Doe <john2@doe2.com>',
                                         'John Doe <john@doe.com>']
    expect(key.id).to eq 'F291A664'
    expect(key.type).to eq :public_key
  end

  it 'parses an external secret key with multiple usernames in gpg 2.0.22 format' do
    # arrange
    gpg_output = <<-EOF
sec::2048:1:9C77A0112E6F7924:1411073355:1474145355:::John Doe <john@doe.com>:
fpr:::::::::38F6F36CBF7D1D54CADE2E2C9C77A0112E6F7924:
uid:::::::::John Doe <john2@doe2.com>:
ssb::2048:1:FE70C2755D731658:1411073355::::
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse_output_external gpg_output

    # assert
    result.should have(1).items
    key = result[0]
    expect(key.fingerprint).to eq '38F6F36CBF7D1D54CADE2E2C9C77A0112E6F7924'
    expect([*key.usernames].sort).to eq ['John Doe <john2@doe2.com>',
                                         'John Doe <john@doe.com>']
    expect(key.id).to eq '2E6F7924'
    expect(key.type).to eq :secret_key
  end

  it 'parses a ring public key with multiple usernames' do
    # arrange
    gpg_output = <<-EOF
tru::1:1411072882:0:3:1:5
pub:-:2048:1:E2165290F291A664:1411070340:1474142340::-:::scESC:
fpr:::::::::85F100D09E9DFF4353DF461CE2165290F291A664:
uid:-::::1411070365::B32D279CBB4B9ABF26BE2CC705D8780D572FC13E::John Doe <john2@doe2.com>:
uid:-::::1411070340::22DFC50E5CED717233C90C47C03E044A7EA483DC::John Doe <john@doe.com>:
sub:-:2048:1:9CB992C6F1BDD31A:1411070340:1474142340:::::e:
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse_output_ring gpg_output

    # assert
    result.should have(1).items
    key = result[0]
    expect(key.fingerprint).to eq '85F100D09E9DFF4353DF461CE2165290F291A664'
    expect([*key.usernames].sort).to eq ['John Doe <john2@doe2.com>',
                                         'John Doe <john@doe.com>']
    expect(key.id).to eq 'F291A664'
    expect(key.type).to eq :public_key
  end

  it 'parses a ring secret key with multiple usernames' do
    # arrange
    gpg_output = <<-EOF
sec::2048:1:9C77A0112E6F7924:1411073355:1474145355:::::::::
fpr:::::::::38F6F36CBF7D1D54CADE2E2C9C77A0112E6F7924:
uid:::::::22DFC50E5CED717233C90C47C03E044A7EA483DC::John Doe <john@doe.com>:
uid:::::::B32D279CBB4B9ABF26BE2CC705D8780D572FC13E::John Doe <john2@doe2.com>:
ssb::2048:1:FE70C2755D731658:1411073355::::::::::
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse_output_ring gpg_output

    # assert
    result.should have(1).items
    key = result[0]
    expect(key.fingerprint).to eq '38F6F36CBF7D1D54CADE2E2C9C77A0112E6F7924'
    expect([*key.usernames].sort).to eq ['John Doe <john2@doe2.com>',
                                         'John Doe <john@doe.com>']
    expect(key.id).to eq '2E6F7924'
    expect(key.type).to eq :secret_key
  end
end