(function () {
  'use strict';

  const navToggle = document.getElementById('navToggle');
  const navMenu = document.getElementById('navMenu');

  if (navToggle && navMenu) {
    navToggle.addEventListener('click', function () {
      navMenu.classList.toggle('active');

      const spans = navToggle.querySelectorAll('span');
      if (navMenu.classList.contains('active')) {
        spans[0].style.transform = 'rotate(45deg) translate(5px, 5px)';
        spans[1].style.opacity = '0';
        spans[2].style.transform = 'rotate(-45deg) translate(7px, -6px)';
      } else {
        spans[0].style.transform = 'none';
        spans[1].style.opacity = '1';
        spans[2].style.transform = 'none';
      }
    });

    const navLinks = navMenu.querySelectorAll('a');
    navLinks.forEach(link => {
      link.addEventListener('click', function () {
        if (window.innerWidth <= 768) {
          navMenu.classList.remove('active');
          const spans = navToggle.querySelectorAll('span');
          spans[0].style.transform = 'none';
          spans[1].style.opacity = '1';
          spans[2].style.transform = 'none';
        }
      });
    });
  }

  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
      const href = this.getAttribute('href');

      if (href === '#') {
        e.preventDefault();
        return;
      }

      const target = document.querySelector(href);
      if (target) {
        e.preventDefault();
        const navHeight = document.querySelector('.navbar').offsetHeight;
        const targetPosition = target.getBoundingClientRect().top + window.pageYOffset - navHeight;

        window.scrollTo({
          top: targetPosition,
          behavior: 'smooth'
        });
      }
    });
  });

  function addCopyButtons() {
    const codeBlocks = document.querySelectorAll('pre code');

    codeBlocks.forEach((codeBlock) => {
      const pre = codeBlock.parentElement;

      const wrapper = document.createElement('div');
      wrapper.style.position = 'relative';

      const copyButton = document.createElement('button');
      copyButton.textContent = 'Copy';
      copyButton.className = 'copy-button';
      copyButton.style.cssText = `
                position: absolute;
                top: 8px;
                right: 8px;
                padding: 4px 12px;
                background-color: rgba(255, 153, 0, 0.9);
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 0.85rem;
                font-weight: 600;
                transition: all 0.2s;
                opacity: 0;
            `;

      pre.parentNode.insertBefore(wrapper, pre);
      wrapper.appendChild(pre);
      wrapper.appendChild(copyButton);

      wrapper.addEventListener('mouseenter', () => {
        copyButton.style.opacity = '1';
      });

      wrapper.addEventListener('mouseleave', () => {
        copyButton.style.opacity = '0';
      });

      copyButton.addEventListener('click', async () => {
        const code = codeBlock.textContent;

        try {
          await navigator.clipboard.writeText(code);
          copyButton.textContent = 'Copied!';
          copyButton.style.backgroundColor = '#28a745';

          setTimeout(() => {
            copyButton.textContent = 'Copy';
            copyButton.style.backgroundColor = 'rgba(255, 153, 0, 0.9)';
          }, 2000);
        } catch (err) {
          console.error('Failed to copy code:', err);
          copyButton.textContent = 'Failed';
          setTimeout(() => {
            copyButton.textContent = 'Copy';
          }, 2000);
        }
      });
    });
  }

  function observeElements() {
    const observerOptions = {
      threshold: 0.1,
      rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.style.opacity = '1';
          entry.target.style.transform = 'translateY(0)';
        }
      });
    }, observerOptions);

    const featureCards = document.querySelectorAll('.feature-card');
    featureCards.forEach((card, index) => {
      card.style.opacity = '0';
      card.style.transform = 'translateY(20px)';
      card.style.transition = `all 0.6s ease ${index * 0.1}s`;
      observer.observe(card);
    });

    const demoItems = document.querySelectorAll('.demo-item');
    demoItems.forEach((item, index) => {
      item.style.opacity = '0';
      item.style.transform = 'translateY(20px)';
      item.style.transition = `all 0.6s ease ${index * 0.15}s`;
      observer.observe(item);
    });

    const docCards = document.querySelectorAll('.doc-card');
    docCards.forEach((card, index) => {
      card.style.opacity = '0';
      card.style.transform = 'translateY(20px)';
      card.style.transition = `all 0.6s ease ${index * 0.1}s`;
      observer.observe(card);
    });
  }

  function updateActiveNavLink() {
    const sections = document.querySelectorAll('section[id]');
    const navLinks = document.querySelectorAll('.nav-menu a[href^="#"]');

    const observerOptions = {
      threshold: 0.3,
      rootMargin: '-100px 0px -60% 0px'
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const id = entry.target.getAttribute('id');
          navLinks.forEach(link => {
            link.style.color = '';
            link.style.backgroundColor = '';

            if (link.getAttribute('href') === `#${id}`) {
              link.style.color = 'var(--primary)';
              link.style.backgroundColor = 'var(--bg-secondary)';
            }
          });
        }
      });
    }, observerOptions);

    sections.forEach(section => observer.observe(section));
  }

  function initLightbox() {
    const demoImages = document.querySelectorAll('.demo-item img');

    demoImages.forEach(img => {
      img.style.cursor = 'zoom-in';

      img.addEventListener('click', function () {
        const overlay = document.createElement('div');
        overlay.style.cssText = `
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background-color: rgba(0, 0, 0, 0.9);
                    z-index: 9999;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    cursor: zoom-out;
                    animation: fadeIn 0.3s ease;
                `;

        const enlargedImg = document.createElement('img');
        enlargedImg.src = this.src;
        enlargedImg.alt = this.alt;
        enlargedImg.style.cssText = `
                    max-width: 90%;
                    max-height: 90%;
                    border-radius: 8px;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
                `;

        overlay.appendChild(enlargedImg);
        document.body.appendChild(overlay);
        document.body.style.overflow = 'hidden';

        overlay.addEventListener('click', function () {
          document.body.removeChild(overlay);
          document.body.style.overflow = '';
        });

        const escHandler = function (e) {
          if (e.key === 'Escape') {
            if (document.body.contains(overlay)) {
              document.body.removeChild(overlay);
              document.body.style.overflow = '';
            }
            document.removeEventListener('keydown', escHandler);
          }
        };
        document.addEventListener('keydown', escHandler);
      });
    });
  }

  function trackEvent(eventName, eventData) {
    console.log('Event tracked:', eventName, eventData);
  }

  document.querySelectorAll('.btn').forEach(btn => {
    btn.addEventListener('click', function () {
      trackEvent('button_click', {
        button_text: this.textContent.trim(),
        button_href: this.getAttribute('href')
      });
    });
  });

  function init() {
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    addCopyButtons();
    initLightbox();
    updateActiveNavLink();

    if (!prefersReducedMotion) {
      observeElements();
    } else {
      document.querySelectorAll('.feature-card, .demo-item, .doc-card').forEach(el => {
        el.style.opacity = '1';
        el.style.transform = 'none';
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
