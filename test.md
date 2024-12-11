<h1 align=center>APTKnowledgeBase</h1>

<h4 align=center>☄️ AURORA | ☁️ LLM | 🌙 PDDL</h4>

## 👋 Resources & Socials
* 📜 [Documentation, training, and use-cases]()
* ✍️ [Aurora's blog]()
* 🌐 [Homepage]()

<p>
  <img src="https://img.shields.io/badge/Python-3.12-red" />
</p>

---

<p align="center">
  <img width="900" src="images/Overview%20of%20AURORA.png" alt="cli output"/>
</p>

---

## 🎉 Introduction
<p><a href="https://arxiv.org/pdf/2407.16928"><img alt="Paper thumbnail" align="right" width="160" src="images/First_page.png"></a></p>

- Introduces AURORA, a PDDL-based cyberattack simulation system.
- Integrates LLMs into PDDL for real-world BAS.
- Automates construction of a 1,800+ action attack space with over 300 chains.
- AURORA generates higher quality attack plans with broader TTP coverage.

Our paper: [From Sands to Mansions: Simulating Full Attack Chain with LLM-Organized Knowledge](https://arxiv.org/pdf/2407.16928) [pdf]



## ✨ Demo
`The .gif of attack chain generated` :

<p align="center">
  <img width="700" align="center" src="https://user-images.githubusercontent.com/9840435/60266022-72a82400-98e7-11e9-9958-f9004c2f97e1.gif" alt="demo"/>
</p>


**Read `Example/` for more details**


## 🚀 Usage

### Installation
Concise installation steps:
```Bash
git clone https://github.com/MCV-ZK/APTKnowledgeBase.git --recursive    #这个需要到时候设置成公共，目前仅供参考
```

Full steps: 
Start by cloning this repository recursively, passing the desired version/release in x.x.x format. This will pull in all available plugins.
```Bash
git clone https://github.com/MCV-ZK/APTKnowledgeBase.git --recursive --tag x.x.x
```
### Download the atomic tests
```
cd ./data
git clone https://github.com/redcanaryco/atomic-red-team.git
```
### Analyze the CTI reports using ChatGPT
```
python aurora/reportAnalyzer/CTIReportAnalyzer.py
```

### Find suitable procedure for each step
```
python aurora/procedureSearcher/procedure_embedding.py
```

### Generate Infrastructrues
```
python aurora/procedureSearcher/infrastructureBuilder/*
```

### Generate CALDERA-based emulation plan and scripts
```
python aurora/procedureSearcher/implementation/*
```



## 🤝 Contributing

Thanks to the following people who have contributed to this project:

* [@scottydocs](https://github.com/scottydocs) 📖
* [@cainwatson](https://github.com/cainwatson) 🐛
* [@calchuchesta](https://github.com/calchuchesta) 🐛

## 👤 Contact

If you want to contact me you can reach me at <your_email@address.com>.
