domain = ARGV[0]
raise '引数でドメイン名 (FQDN) を指定してください' unless domain.is_a?(String)

require 'openssl'
require 'pathname'

OpenSSL::Random.seed File.read('/dev/random', 16)
digest = OpenSSL::Digest::SHA1.new

issu_cer = OpenSSL::X509::Certificate.new File.read('ca/ca.pem')
issu = issu_cer.issuer
issu_rsa = OpenSSL::PKey::RSA.new File.read('ca/ca_private_key.pem')

sub = issu.clone
sub.add_entry 'CN', domain

sub_rsa = OpenSSL::PKey::RSA.generate 2048
dir = Pathname.new domain
Dir.mkdir dir unless dir.exist?
File.open "#{domain}/#{domain}.key", 'wb' do |f|
  f.write sub_rsa.export
end

sub_cer = OpenSSL::X509::Certificate.new
sub_cer.not_before = Time.now
sub_cer.not_after = Time.now + 100 * 365 * 24 * 60 * 60
sub_cer.public_key = sub_rsa.public_key
new_serial = File.read('ca/serial.txt').to_i + 1
File.open 'ca/serial.txt', 'wb' do |f|
  f.write new_serial
end
sub_cer.serial = new_serial
sub_cer.issuer = issu
sub_cer.subject = sub
ex = OpenSSL::X509::Extension.new 'basicConstraints', OpenSSL::ASN1.Sequence([OpenSSL::ASN1::Boolean(false)])
sub_cer.add_extension ex
ex = OpenSSL::X509::Extension.new 'nsCertType', 'server'
sub_cer.add_extension ex
sub_cer.sign issu_rsa, digest
File.open "#{domain}/#{domain}.crt", 'wb' do |f|
  f.write sub_cer.to_pem
end
