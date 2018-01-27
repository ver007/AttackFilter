# encoding: utf-8
require 'logstash/devutils/rspec/spec_helper'
require 'logstash/filters/attackfilter'

describe LogStash::Filters::Attackfilter do
    describe 'parser attack' do
        let(:config) do
            <<-CONFIG
            filter {
                attackfilter {
                    source => "%{message}"
                }
            }
            CONFIG
        end

        sample('message' => '2016-01-01 23:59:11 8.8.8.3 GET /5/plus/search.php?keyword=as&typeArra - 80 - 60.17.253.141 Mozilla/5.0+(Windows+NT+6.2;+WOW64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/31.0.1650.63+Safari/537.36 200 0 0 78') do
            expect(subject.get('attack_info')).to eq({})
        end
    end
end
