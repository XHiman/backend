import random

def generate_mnemonic(entries):
    """
    Takes a list of names/facts/keywords and generates mnemonics for each.
    Returns a list of mnemonic sentences.
    """
    templates = [
        "Remember {entry} by thinking: '{entry} stands for {trait}.'",
        "To recall {entry}, imagine it as {mental_image}.",
        "{entry}: associate it with '{trait}' for easy memory.",
        "{entry} always reminds me of {mental_image}."
    ]
    traits = [
        "bravery", "wisdom", "speed", "happiness", "adventure",
        "kindness", "energy", "focus", "calm", "strength"
    ]
    images = [
        "a flying kite", "a roaring lion", "a sunny beach",
        "a stack of books", "a blooming flower", "a shiny trophy",
        "a cozy cabin", "a sprinting cheetah", "an old oak tree"
    ]
    
    mnemonics = []
    for entry in entries:
        template = random.choice(templates)
        trait = random.choice(traits)
        mental_image = random.choice(images)
        # Fill the template with relevant info
        mnemonic = template.format(entry=entry, trait=trait, mental_image=mental_image)
        mnemonics.append(mnemonic)
    return mnemonics

# Example usage:
names_or_facts = ["Albert Einstein", "Photosynthesis", "Python", "E=mc^2"]
mnemonics = generate_mnemonic(names_or_facts)

for m in mnemonics:
    print(m)
