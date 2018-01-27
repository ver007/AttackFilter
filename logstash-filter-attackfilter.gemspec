Gem::Specification.new do |s|

  s.name = 'logstash-filter-attackfilter'
  s.version = '1.0.6'
  s.licenses = ['Apache License (2.0)']
  s.summary = '分析 WEBLOG 中存在的攻击行为.'
  s.description = '用与通过规则分析日志文件中存在的攻击行为，请安装到 $LS_HOME/bin/logstash-plugin '
  s.authors = ['Elastic']
  s.email = 'anbai@anbai-inc.com'
  s.homepage = "http://www.elastic.co/guide/en/logstash/current/index.html"
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','lib/*','spec/**/*','vendor/**/*','*.gemspec','*.yaml','*.md','Gemfile','LICENSE']

  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = {'logstash_plugin' => "true", 'logstash_group' => "filter" }

  # Gem dependencies
  s.add_runtime_dependency 'logstash-core-plugin-api', '>= 1.60', '<= 2.99'

  s.add_runtime_dependency 'lru_redux',  '~> 1.1', '>= 1.1.0'
  s.add_development_dependency 'logstash-devutils','~> 0'
end
