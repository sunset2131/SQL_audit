BUS-001	硬性	业务SQL内容审核	通用	严禁包含DDL操作（TRUNCATE/CREATE/ALTER/DROP等结构变更），适用于业务SQL及存储过程内部SQL	检查SQL是否包含DDL关键字	业务SQL包含禁止的DDL操作：检测到结构变更语句。	将结构变更移出业务SQL，按DDL流程单独提交。
BUS-002	硬性	业务SQL内容审核	通用	DELETE/UPDATE必须有有效WHERE（WHERE 1=1 AND id=?含限制条件不算违规）	检查DELETE/UPDATE是否包含有效WHERE	无条件全表更新/删除：语句缺少有效WHERE条件；位置：业务SQL。	增加能够限定本次业务数据范围的有效条件。
BUS-003	硬性	业务SQL内容审核	通用	禁止SELECT *和alias.*	检查SELECT列表是否使用*	使用SELECT *：未明确列出所需字段。	只列出业务实际需要的字段。
BUS-004	硬性	业务SQL内容审核	通用	必须使用绑定变量占位（?/:name/$1等），禁止硬编码常量。示例值由MAT-011检查	检查SQL是否使用绑定占位	绑定变量使用不符合要求：业务参数未使用占位。	使用绑定变量替代业务常量。
BUS-005	硬性	业务SQL内容审核	通用	NULL判断必须使用IS NULL/IS NOT NULL，禁止= NULL/!= NULL	检查NULL判断语法	NULL判断错误：使用了与NULL的等值或不等值比较。	改用IS NULL或IS NOT NULL。
BUS-006	建议	业务SQL内容审核	通用	尽量避免NOT/!=/<>/NOT EXISTS/NOT IN等负向查询	检查负向查询条件，有则提示风险	负向查询风险：使用了<operator>，可能导致索引利用不足；位置：WHERE条件。	优先改写为正向条件；无法改写时补充执行计划、数据量和业务必要性供二次确认。
BUS-007	硬性	业务SQL内容审核	通用	同一字段多等值OR必须改写为IN()（不同字段间OR不适用）	检查同字段是否使用多个OR连接	同字段重复OR：同一字段的多个等值条件未使用IN。	将同字段等值OR改写为IN(...)。
BUS-008	硬性	业务SQL内容审核	通用	禁止前导通配查询（LIKE %xx和LIKE %xx%）	检查LIKE模式是否以%开头	前导通配查询：LIKE参数以'%'开始，可能无法使用普通索引。	改为精确或前缀匹配；业务必须包含匹配时提交必要性和影响说明供二次确认。
BUS-009	硬性	业务SQL内容审核	通用	JOIN不得超过3张表（同表不同别名按实际计数）	统计JOIN的表数量	多表关联超过上限：业务SQL JOIN超过3张表。	改为分步查询、应用层组装或字段冗余方案。
BUS-010	硬性	业务SQL内容审核	通用	必须使用ANSI JOIN语法（INNER JOIN/LEFT JOIN），禁止逗号分隔隐式连接	检查JOIN语法是否为标准ANSI写法	使用逗号隐式连接：未采用ANSI JOIN语法。	改用INNER JOIN、LEFT JOIN等明确连接方式和ON条件。
BUS-011	硬性	业务SQL内容审核	通用	禁止SELECT...FOR UPDATE等显式加锁	检查SQL是否包含FOR UPDATE	使用显式锁：业务SQL包含SELECT...FOR UPDATE等加锁操作。	移除显式锁并按既定并发控制方案重新设计。
BUS-012	硬性	业务SQL内容审核	通用	批量INSERT单次VALUES不超过5000个元组	检查INSERT的VALUES列表数量	批量插入超过上限：单条INSERT的VALUES数量超过5000。	拆分批次，确保每条INSERT不超过5000个VALUES元组。
BUS-013	硬性	业务SQL内容审核	通用	禁止使用随机排序函数（RAND()/RANDOM()/DBMS_RANDOM.VALUE等）	检查ORDER BY是否使用随机排序函数	使用随机排序函数：检测到<function>随机查询。	移除随机排序函数，改用可控的抽样或随机键方案。
