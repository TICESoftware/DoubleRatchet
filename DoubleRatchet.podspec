Pod::Spec.new do |s|

  s.name          = "DoubleRatchet"
  s.version       = "1.1.8"
  s.summary       = "Double Ratchet protocol."
  s.platform      = :ios, "11.0"
  s.swift_version = "5.0"

  s.homepage      = "http://letsmeet.anbion.de"

  s.author        = { "TICE Software UG (haftungsbeschränkt)" => "contact@ticeapp.com" }
  s.source        = { :git => "git@github.com:TICESoftware/DoubleRatchet.git", :tag => "#{s.version}" }

  s.source_files  = "Sources/**/*"

  s.dependency "Sodium"
  s.dependency "HKDF"

end
