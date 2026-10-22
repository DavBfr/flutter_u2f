#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint hid_macos.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'u2f'
  s.version          = '0.0.1'
  s.summary          = 'A new flutter plugin project.'
  s.description      = <<-DESC
A new flutter plugin project.
                       DESC
  s.homepage         = 'http://example.com'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Your Company' => 'email@example.com' }
  s.source           = { :path => '.' }
  # Swift Package Manager (`u2f/Package.swift`) is the primary dependency
  # manager. CocoaPods stays supported for applications that have not enabled
  # SPM: it compiles the same sources and uses the `hidapi` pod.
  s.source_files     = 'u2f/Sources/u2f/**/*.{h,c}'
  s.public_header_files = 'u2f/Sources/u2f/include/**/*.h'
  s.dependency 'FlutterMacOS'
  s.dependency 'hidapi'

  s.platform = :osx, '12.0'
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'HEADER_SEARCH_PATHS' => '"${PODS_TARGET_SRCROOT}/u2f/Sources/u2f/include"',
    'SWIFT_VERSION' => '5.0',
  }
  s.swift_version = '5.0'
end
