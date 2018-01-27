# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "lru_redux"
require "tempfile"
require "thread"
require 'parser'

class LogStash::Filters::Attackfilter < LogStash::Filters::Base
    LOOKUP_CACHE = LruRedux::ThreadSafeCache.new(1000)

    # 插件名称
    config_name "attackfilter"

    # suorce
    config :source, :validate => :string, :required => true

    # default.yaml 用于分析攻击请求的正则文件
    # 文件格式参照 <https://github.com/ua-parser/uap-core/blob/master/regexes.yaml>
    config :yamlfile, :validate => :array
    # 存在于es里的类型名称
    config :target, :validate => :string, :default => "attack_info"
    # 存在于 analysis_result 里的子类型
    config :fields, :validate => :array, :default => ['attack_status',
                                                      'attack_status_name',

                                                      # 攻击类型和是否组合攻击
                                                      'risk_level',
                                                      'risk_desc',

                                                      'attack_detail',

                                                      # 攻击类型信息
                                                      'attack_type_id',
                                                      'attack_type_name',

                                                      # 攻击产生位置
                                                      'attack_place',

                                                      # 行为信息
                                                      'action_id',
                                                      'action_desc',
                                                      'action_risk_level',

                                                      # 攻击规则信息
                                                      'attack_rule' ,
                                                      'attack_rule_id',
                                                      'attack_source_place',

                                                      # 扫描器信息及其他项目
                                                      'scaner_status',
                                                      'scaner_rule',
                                                      'scaner_name',
                                                      'other']

    # 子类型前缀
    config :prefix, :validate => :string, :default => 'attack_'
    # 缓存大小
    config :lru_cache_size, :validate => :number, :default => 1000

    ###
    # 注册插件
    def register
        if @yamlfile.nil?
            begin
                @parser = AttackParser::Parser.new
            rescue
                begin

                    path = ::File.expand_path('../../../yamlfile/', ::File.dirname(__FILE__))
                    @yamlfile = traverse_dir(path)

                    if @yamlfile.size==0
                        path = ::File.expand_path('../../../default.yaml', ::File.dirname(__FILE__))
                        unless File.file? path
                            puts("\n\033[01;33m[!]   Load RuleFile list Error: No such file or directory \033[0m       \n", path)
                            exit(0)
                        end
                        @yamlfile = [path]
                    end

                    if @yamlfile.size!=0
                        puts "\n\033[01;34m[*]  Load RuleFile list:\033[0m\n", @yamlfile, "\n"
                        @parser = AttackParser::Parser.new(:patterns_path => @yamlfile)
                    end

                rescue => ex
                    raise("\n\033[01;33m[!]   Load RuleFile list Error:\033[0m #{ex} #{@yamlfile}\n")
                end
            end
        end

        LOOKUP_CACHE.max_size = @lru_cache_size

    end

    ###
    # 插件主函数
    # event 数据集
    def filter(event)

        message = event.get(@source)

        message = message.first if message.is_a?(Array)
        if message.nil? || message.empty?
            return
        end

        begin
            return_info = lookup_url([message])
        rescue StandardError => e
            @logger.error("处理数据出错 1001", :exception => e, :field => url, :event => event)
            return
        end
        return unless return_info
        apply_geodata(return_info, event)
        filter_matched(event)
    end

    ###
    # 数据缓存处理
    # data 待分析数据
    def lookup_url(data)
        return unless data
        cached = LOOKUP_CACHE[data]
        return cached if cached

        begin
            analysis_result = @parser.parse(data)
                # puts 'analysis_result:', analysis_result
        rescue NoMethodError => e
            @logger.error("处理数据出错 1002", :exception => e)
        end

        LOOKUP_CACHE[data] = analysis_result
        analysis_result
    end

    ###
    # 分析结果插入方法
    # analysis_result 分析结果
    # event 数据列
    def apply_geodata(analysis_result, event)

        # 判断对象是否存在
        return false if analysis_result.nil?

        # 判断mapping是否存在target 不存在即添加
        event.set(@target, {}) if event.get(@target).nil?

        # 判断是否存在 不存在则返回
        return false if analysis_result.empty?

        analysis_result.each do |key, value|

            if @fields.include?(key) && value
                # 将分析数据插入到es
                event.set("[#{@target}][#{key}]", value)
            end
        end
    end

    ##
    # 遍历规则文件
    # path 配置文件目录
    def traverse_dir(file_path)
        files=[]
        if File.directory? file_path
            Dir.foreach(file_path) do |file|
                file_path+='/' unless file_path.end_with? '/'
                if file.end_with? '.yaml'
                    path = ::File.expand_path(file_path+file, ::File.dirname(__FILE__))
                    files+=[path]
                end
            end
            files
        end
    end
end

