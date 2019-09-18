
  Pod::Spec.new do |s|
    s.name = 'CapacitorPluginAes256Encryption'
    s.version = '0.0.1'
    s.summary = "This capacitor ionic plugin allows you to perform AES 256 encryption and decryption on the plain text. It's a cross-platform plugin which supports both Android and iOS. The encryption and decryption are performed on the device native layer so that the performance is much faster."
    s.license = 'MIT'
    s.homepage = 'https://github.com/Ideas2IT/cordova-aes256.git'
    s.author = 'Ideas2it'
    s.source = { :git => 'https://github.com/Ideas2IT/cordova-aes256.git', :tag => s.version.to_s }
    s.source_files = 'ios/Plugin/**/*.{swift,h,m,c,cc,mm,cpp}'
    s.ios.deployment_target  = '11.0'
    s.dependency 'Capacitor'
  end