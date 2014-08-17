require 'rspec'
$: << File.join(File.dirname(__FILE__), '../../../libraries')
require 'key_details'
require 'gpg_parser'

describe BswTech::Gpg::GpgParser do
  it 'parses a 1 ring secret key' do
    # arrange
    gpg_output = <<-EOF
/Users/brady/.gnupg/secring.gpg
-------------------------------
sec   2048R/1E7D2809 2014-06-11 [expires: 2018-06-10]
      Key fingerprint = FEF5 2674 8083 5871 C5EC  3382 3180 12D6 1E7D 2809
uid                  Brady Wied <brady@bswtechconsulting.com>
ssb   2048R/DF94190A 2014-06-11

    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse :ring, gpg_output

    # assert
    result.should have(1).items
    key = result[0]
    key.fingerprint.should == 'FEF5 2674 8083 5871 C5EC  3382 3180 12D6 1E7D 2809'
    key.username.should == 'Brady Wied <brady@bswtechconsulting.com>'
    key.id.should == '1E7D2809'
  end

  it 'parses multiple ring secret keys' do
    # arrange
    gpg_output = <<-EOF
/Users/brady/.gnupg/secring.gpg
-------------------------------
sec   2048R/1E7D2809 2014-06-11 [expires: 2018-06-10]
      Key fingerprint = FEF5 2674 8083 5871 C5EC  3382 3180 12D6 1E7D 2809
uid                  Brady Wied <brady@bswtechconsulting.com>
ssb   2048R/DF94190A 2014-06-11

sec   2048R/1E7D2808 2014-06-11 [expires: 2018-06-10]
      Key fingerprint = BEF5 2674 8083 5871 C5EC  3382 3180 12D6 1E7D 2809
uid                  Brady2 Wied <brady@bswtechconsulting.com>
ssb   2048R/DF94190A 2014-06-11

    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse :ring, gpg_output

    # assert
    result.should have(2).items
    key = result[0]
    key.fingerprint.should == 'FEF5 2674 8083 5871 C5EC  3382 3180 12D6 1E7D 2809'
    key.username.should == 'Brady Wied <brady@bswtechconsulting.com>'
    key.id.should == '1E7D2809'
    key = result[1]
    key.fingerprint.should == 'BEF5 2674 8083 5871 C5EC  3382 3180 12D6 1E7D 2809'
    key.username.should == 'Brady2 Wied <brady@bswtechconsulting.com>'
    key.id.should == '1E7D2808'
  end

  it 'parses 1 ring public key' do
    # arrange
    gpg_output = <<-EOF
                          -----------------
                          pub   2048R/390AA6C9 2014-06-10 [expires: 2016-06-09]
                                Key fingerprint = 4D1C F328 8469 F260 C211  9B9F 76C9 5D74 390A A6C9
                          uid                  BSW Tech DB Backup db_dev (WAL-E/S3 Encryption key) <db_dev@wale.backup.bswtechconsulting.com>
                          sub   2048R/1A0B6924 2014-06-10 [expires: 2016-06-09]
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse :ring, gpg_output

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
    result = BswTech::Gpg::GpgParser.new.parse :ring, gpg_output

    # assert
    result.should have(1).items
    key = result[0]
    key.fingerprint_no_whitespace.should == '4D1CF3288469F260C2119B9F76C95D74390AA6C9'
  end

  it 'parses properly with no ring keys there' do
    # arrange
    gpg_output = ''

    # act
    result = BswTech::Gpg::GpgParser.new.parse :ring, gpg_output

    # assert
    result.should have(0).items
  end

  it 'parses properly with multiple public ring keys there' do
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
    result = BswTech::Gpg::GpgParser.new.parse :ring, gpg_output

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

  it 'parses 1 secret external key OK' do
    # arrange
    gpg_output = <<-EOF
  sec  2048R/33AE3E6C 2014-08-17 pkg_key dev (pkg_key) <dev@aptly.bswtechconsulting.com>
        Key fingerprint = 7B11 C141 0667 3B53 46A6  5351 F44B 4C68 33AE 3E6C
  ssb  2048R/175EAAB1 2014-08-17
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse :external, gpg_output

    # assert
    result.should have(1).items
    key = result[0]
    key.fingerprint.should == '7B11 C141 0667 3B53 46A6  5351 F44B 4C68 33AE 3E6C'
    key.username.should == 'pkg_key dev (pkg_key) <dev@aptly.bswtechconsulting.com>'
    key.id.should == '33AE3E6C'
  end

  it 'parses 1 public external key OK' do
    # arrange
    gpg_output = <<-EOF
    pub  2048R/33AE3E6C 2014-08-17 pkg_key dev (pkg_key) <dev@aptly.bswtechconsulting.com>
          Key fingerprint = 7B11 C141 0667 3B53 46A6  5351 F44B 4C68 33AE 3E6C
    sub  2048R/175EAAB1 2014-08-17 [expires: 2016-08-16]
    EOF

    # act
    result = BswTech::Gpg::GpgParser.new.parse :external, gpg_output

    # assert
    result.should have(1).items
    key = result[0]
    key.fingerprint.should == '7B11 C141 0667 3B53 46A6  5351 F44B 4C68 33AE 3E6C'
    key.username.should == 'pkg_key dev (pkg_key) <dev@aptly.bswtechconsulting.com>'
    key.id.should == '33AE3E6C'
  end
end