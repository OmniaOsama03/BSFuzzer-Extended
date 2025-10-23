#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
环境变量设置脚本
从配置文件中读取API密钥并设置为环境变量
"""

import os
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def setup_env_variables():
    """设置环境变量"""
    config_path = os.path.join(os.path.dirname(__file__), "model_key.json")
    
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        
        # 读取API密钥
        api_keys = config.get("llm_key", {})
        
        # 设置环境变量
        os.environ["OPENAI_API_KEY"] = api_keys.get("gpt_api_key", "")
        os.environ["GOOGLE_API_KEY"] = api_keys.get("google_api_key", "")
        os.environ["ANTHROPIC_API_KEY"] = api_keys.get("claude_api_key", "")
        os.environ["DEEPSEEK_API_KEY"] = api_keys.get("deepseek_api_key", "")
        os.environ["GROK_API_KEY"] = api_keys.get("grok_api_key", "")
        os.environ["ALI_API_KEY"] = api_keys.get("ali_api_key", "")
        
        logger.info("环境变量设置完成")
        
        # 输出环境变量（仅用于调试，实际使用时请移除）
        logger.debug("OPENAI_API_KEY: %s", os.environ["OPENAI_API_KEY"][:5] + "..." if os.environ["OPENAI_API_KEY"] else "未设置")
        logger.debug("GOOGLE_API_KEY: %s", os.environ["GOOGLE_API_KEY"][:5] + "..." if os.environ["GOOGLE_API_KEY"] else "未设置")
        
    except Exception as e:
        logger.error("设置环境变量时出错: %s", str(e))
        raise

if __name__ == "__main__":
    setup_env_variables() 