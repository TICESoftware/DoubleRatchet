Pod::Spec.new do |s|

  s.name          = "DoubleRatchet"
  s.version       = "1.1.6"
  s.summary       = "Double Ratchet protocol."
  s.platform      = :ios, "11.0"
  s.swift_version = "5.0"

  s.homepage      = "http://letsmeet.anbion.de"

  s.author        = { "Anbion" => "letsmeet@anbion.de" }
  s.source        = { :git => "git@github.com:AnbionApps/DoubleRatchet.git", :tag => "#{s.version}" }

  s.source_files  = "Sources/**/*"

  s.dependency "Sodium"
  s.dependency "HKDF"

end
