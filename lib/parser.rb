# encoding: utf-8

require 'yaml'

module AttackParser
    class Parser
        attr_reader :patterns_path

        ###
        # 分析类初始化
        # options 初始化需要的参数
        def initialize(options={})
            @patterns_path = options[:patterns_path]
            @regexs = load_patterns(patterns_path)
        end

        ###
        # 分析类分析方法入口
        # data 待分析的字符
        def parse(data)
            # 攻击识别
            analysis_match(data, @regexs)
        end

        private

        ###
        # 正则匹配方法
        # data 待分析的字符
        # regex_list 用于匹配的正则集合
        def analysis_match(data, regex_list)

            regex_type=''
            return_info={# 攻击状态
                         'attack_status' => 0,
                         'attack_status_name' => '正常请求',

                         # 攻击类型和是否组合攻击
                         'risk_level' => 0,
                         'risk_desc' => '',

                         'attack_detail' => '',

                         # 攻击类型信息
                         'attack_type_id' => 0,
                         'attack_type_name' => '',

                         # 攻击产生位置
                         'attack_place' => '',

                         # 行为信息
                         'action_id' => [],
                         'action_desc' => [],
                         'action_risk_level' => 0,

                         # 攻击规则信息
                         'attack_rule' => [],
                         'attack_rule_id' => [],
                         'attack_source_place' => [],

                         # 扫描器信息及其他项目
                         'scaner_status' => 0,
                         'scaner_rule' => 0,
                         'scaner_name' => '',
                         'other' => '',
            }


            regex_list.each do |regextype, regexdict|
                type_num = []
                regexdict.each do |regex|

                    # 判断是否同一规则类型
                    if regex_type == regex['subtype']
                        next
                    end

                    # 正则匹配是否符合规则
                    message = regex['regex'].match(data[0])

                    # 对正则结果进行处理
                    if message
                        case regextype
                            when 'attackregex'

                                # 攻击状态
                                return_info['attack_status']=1
                                return_info['attack_status_name']='攻击请求'

                                # 攻击等级
                                return_info['risk_level']= regex['level'] if return_info['attack_level'].nil?
                                return_info['risk_desc']= regex['leveldesc']

                                # 攻击类型信息
                                if return_info['attack_type_id']<regex['typeid']
                                    return_info['attack_type_id']=regex['typeid']
                                    return_info['attack_type_name']=regex['typename']
                                end

                                # 攻击产生位置
                                return_info['attack_place']=regex['place']

                                # 行为信息
                                return_info['action_id']+=[regex['actionid']]
                                return_info['action_desc']+=[regex['actiondesc']]
                                return_info['action_risk_level']=regex['actionlevel']

                                # 攻击规则信息
                                if return_info['attack_rule_id'].include? regex['id']
                                    puts ''
                                else
                                    return_info['attack_rule_id']+= [regex['id']]
                                    return_info['attack_rule'].push(regex['regex'].source)
                                    return_info['attack_source_place'].push(message[0])
                                end

                                # 攻击是否组合攻击
                                if return_info['attack_rule_id'].length==1
                                    return_info['attack_detail'] ='攻击为普通攻击'
                                elsif return_info['attack_rule_id'].length>1
                                    return_info['attack_detail'] ='攻击为组合攻击'
                                end

                                regex_type = regex['typename']

                            # when 'scanerregex'
                            #     return_info['scaner_status']=1
                            #     return_info['scaner_rule']=regex['regexid']
                            #     return_info['scaner_name']=regex['typename']
                            #
                            # when 'other'
                            #     return_info['other']=regex['typename']
                            # else
                            #     raise Exception.new("[#{regextype}] is not a supported field option.")
                        end
                    end
                end
            end
            return_info
        end

        ###
        # 用于读取特征规则文件
        # paths 特征规则文件路径
        def load_patterns(paths)
            yml=nil
            paths.each do |path|
                begin
                    yml = YAML.load_file(path)
                rescue => e
                    @logger.error(" Rule File error : #{path}")
                    raise Exception.new("[#{e}] \"#{path}\" Rule File error .")
                end
                yml.each_pair do |type, patterns|
                    patterns.each do |pattern|
                        begin
                            pattern['regex'] = Regexp.new(pattern['regex'])
                        rescue => ex
                            puts "\n\033[01;33m[!] Regexp Compile Error:\033[0m \nregexp_id = #{pattern['id']} \nerror_info = #{ex} \n\n"
                            # raise("\n\033[01;33m[!]   Regexp Compile Error:\033[0m id = #{pattern['id']} error_info = #{ex} \n")
                            # raise Exception.new("[!] Regexp Compile Error: [#{e}] \"#{path}\" Rule File error .")
                        end
                    end
                end
            end
            yml
        end
    end
end

