require 'openssl'
require 'pathname'
require 'yaml'

OpenSSL::Random.seed File.read('/dev/random', 16)
digest = OpenSSL::Digest::SHA1.new

conf = YAML.load File.read('config.yml')
issu = OpenSSL::X509::Name.new
['C', 'ST', 'DC', 'O', 'CN'].each do |param|
  issu.add_entry param, conf[param]
end

issu_rsa = OpenSSL::PKey::RSA.generate 2048
ca_dir = Pathname.new 'ca'

raise 'すでに CA が作成されています。作り直す場合は、ca フォルダごと削除してください。' if (ca_dir + 'ca.pem').exist?

Dir.mkdir ca_dir unless ca_dir.exist?
File.open (ca_dir + 'ca_private_key.pem'), 'wb' do |f|
  f.write issu_rsa.export
end

issu_cer = OpenSSL::X509::Certificate.new
issu_cer.not_before = Time.now
issu_cer.not_after = Time.now + 100 * 365 * 24 * 60 * 60
issu_cer.public_key = issu_rsa.public_key

File.open (ca_dir + 'serial.txt'), 'wb' do |f|
  f.write 1
end
issu_cer.serial = 1
issu_cer.issuer = issu
issu_cer.subject = issu
ex = OpenSSL::X509::Extension.new 'basicConstraints', OpenSSL::ASN1.Sequence([OpenSSL::ASN1::Boolean(true)])
issu_cer.add_extension ex
issu_cer.sign issu_rsa, digest
File.open (ca_dir + 'ca.pem'), 'wb' do |f|
  f.write issu_cer.to_pem
end
