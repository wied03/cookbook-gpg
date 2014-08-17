require 'rspec'
$: << File.join(File.dirname(__FILE__), '../../../libraries')
require 'key_details'
require 'gpg_parser'

describe BswTech::Gpg::GpgParser do

  it 'parses properly when 1 key is there' do
    # arrange
    gpg_output = <<-EOF
                          -----------------
                          pub   2048R/390AA6C9 2014-06-10 [expires: 2016-06-09]
                                Key fingerprint = 4D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
                          uid                  BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
                          sub   2048R/1A0B6924 2014-06-10 [expires: 2016-06-09]
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse gpg_output

    # assert
    result.should have(1).items
    key = result[0]
    key.fingerprint.should == '4D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9'
    key.username.should == 'BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>'
    key.id.should == '390AA6C9'
  end

  it 'gets fingerprint without whitespace' do
    # arrange
    gpg_output = <<-EOF
                          -----------------
                          pub   2048R/390AA6C9 2014-06-10 [expires: 2016-06-09]
                                Key fingerprint = 4D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
                          uid                  BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
                          sub   2048R/1A0B6924 2014-06-10 [expires: 2016-06-09]
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse gpg_output

    # assert
    result.should have(1).items
    key = result[0]
    key.fingerprint_no_whitespace.should == '4D1CF3288469F260C2119B9F76C95D74390AA6C9'
  end

  it 'parses properly with no keys there' do
    # arrange
    gpg_output = ''

    # act
    result = BswTech::Gpg::GpgParser.new.parse gpg_output

    # assert
    result.should have(0).items
  end

  it 'parses properly with multiple keys there' do
    # arrange
    gpg_output = <<-EOF
-----------------
pub   2048R/390AA6C9 2014-06-10 [expires: 2016-06-09]
      Key fingerprint = 5D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
uid                  CSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
sub   2048R/1A0B6924 2014-06-10 [expires: 2016-06-09]

pub   2048R/AA72CC9B 2014-06-11 [expires: 2016-06-10]
      Key fingerprint = 566F 8148 FA10 1FAD 50A1  0038 4DAF 5792 AA72 CC9B
uid                  BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
sub   2048R/03A096FD 2014-06-11 [expires: 2016-06-10]
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse gpg_output

    # assert
    result.should have(2).items
    key = result[0]
    key.fingerprint.should == '5D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9'
    key.username.should == 'CSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>'
    key.id.should == '390AA6C9'
    key = result[1]
    key.fingerprint.should == '566F 8148 FA10 1FAD 50A1  0038 4DAF 5792 AA72 CC9B'
    key.username.should == 'BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>'
    key.id.should == 'AA72CC9B'
  end
end