(function () {
  'use strict';

  document.documentElement.classList.add('js');

  const prefersReducedMotion = window.matchMedia(
    '(prefers-reduced-motion: reduce)'
  ).matches;

  function initNavigation() {
    const toggle = document.getElementById('navToggle');
    const menu = document.getElementById('navMenu');

    if (!toggle || !menu) {
      return;
    }

    function setMenu(open) {
      const mobile = window.matchMedia('(max-width: 820px)').matches;
      menu.classList.toggle('is-open', open);
      menu.hidden = mobile && !open;
      toggle.setAttribute('aria-expanded', String(open));
      toggle.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
    }

    setMenu(false);

    toggle.addEventListener('click', function () {
      setMenu(toggle.getAttribute('aria-expanded') !== 'true');
    });

    menu.querySelectorAll('a').forEach(function (link) {
      link.addEventListener('click', function () {
        setMenu(false);
      });
    });

    document.addEventListener('click', function (event) {
      if (
        toggle.getAttribute('aria-expanded') === 'true' &&
        !menu.contains(event.target) &&
        !toggle.contains(event.target)
      ) {
        setMenu(false);
      }
    });

    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && toggle.getAttribute('aria-expanded') === 'true') {
        setMenu(false);
        toggle.focus();
      }
    });

    window.addEventListener('resize', function () {
      setMenu(false);
    });
  }

  function initActiveNavigation() {
    const links = Array.from(document.querySelectorAll('.nav-link[href^="#"]'));
    const linkById = new Map(
      links.map(function (link) {
        return [link.getAttribute('href').slice(1), link];
      })
    );
    const sections = Array.from(linkById.keys())
      .map(function (id) {
        return document.getElementById(id);
      })
      .filter(Boolean);

    if (!('IntersectionObserver' in window) || sections.length === 0) {
      return;
    }

    const observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) {
            return;
          }

          links.forEach(function (link) {
            link.removeAttribute('aria-current');
          });

          const current = linkById.get(entry.target.id);
          if (current) {
            current.setAttribute('aria-current', 'true');
          }
        });
      },
      {
        rootMargin: '-30% 0px -62% 0px',
        threshold: 0
      }
    );

    sections.forEach(function (section) {
      observer.observe(section);
    });
  }

  function wait(duration) {
    return new Promise(function (resolve) {
      window.setTimeout(resolve, duration);
    });
  }

  async function playTerminalSequence(sequence) {
    const command = sequence.querySelector('[data-terminal-command]');
    const commandLine = command && command.closest('[data-terminal-step]');
    const steps = Array.from(sequence.querySelectorAll('[data-terminal-step]'));

    if (!command || !commandLine || steps.length === 0) {
      sequence.classList.add('is-complete');
      return;
    }

    const originalCommand = command.textContent;

    try {
      sequence.classList.add('is-animated');
      command.textContent = '';
      commandLine.classList.add('is-visible');
      await wait(250);

      for (const character of originalCommand) {
        command.textContent += character;
        await wait(32);
      }

      await wait(220);

      for (const step of steps) {
        if (step === commandLine) {
          continue;
        }

        step.classList.add('is-visible');
        await wait(step.classList.contains('terminal-result') ? 320 : 145);
      }

      await wait(100);
      sequence.classList.add('is-complete');
    } catch (_error) {
      command.textContent = originalCommand;
      sequence.classList.remove('is-animated');
      sequence.classList.add('is-complete');
    }
  }

  function initTerminalSequence() {
    const sequence = document.querySelector('[data-terminal-sequence]');

    if (!sequence) {
      return;
    }

    if (prefersReducedMotion) {
      sequence.classList.add('is-complete');
      return;
    }

    let hasPlayed = false;
    const playOnce = function () {
      if (hasPlayed) {
        return;
      }
      hasPlayed = true;
      playTerminalSequence(sequence);
    };

    if (!('IntersectionObserver' in window)) {
      playOnce();
      return;
    }

    const observer = new IntersectionObserver(
      function (entries) {
        if (entries.some(function (entry) { return entry.isIntersecting; })) {
          observer.disconnect();
          playOnce();
        }
      },
      { threshold: 0.35 }
    );

    observer.observe(sequence);
  }

  function initRevealAnimations() {
    const elements = Array.from(document.querySelectorAll('.reveal'));

    if (
      elements.length === 0 ||
      prefersReducedMotion ||
      !('IntersectionObserver' in window)
    ) {
      elements.forEach(function (element) {
        element.classList.add('is-visible');
      });
      return;
    }

    const observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-visible');
            observer.unobserve(entry.target);
          }
        });
      },
      {
        threshold: 0.08,
        rootMargin: '0px 0px -40px 0px'
      }
    );

    elements.forEach(function (element) {
      observer.observe(element);
    });

    window.requestAnimationFrame(function () {
      document.documentElement.classList.add('reveal-ready');
    });
  }

  function copyWithFallback(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }

    return new Promise(function (resolve, reject) {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.setAttribute('readonly', '');
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();

      try {
        const copied = document.execCommand('copy');
        document.body.removeChild(textarea);
        copied ? resolve() : reject(new Error('Copy command failed'));
      } catch (error) {
        document.body.removeChild(textarea);
        reject(error);
      }
    });
  }

  function initCopyButtons() {
    const status = document.getElementById('copyStatus');

    document.querySelectorAll('[data-copy-target]').forEach(function (button) {
      let resetTimer;

      button.addEventListener('click', async function () {
        const target = document.getElementById(button.dataset.copyTarget);
        if (!target) {
          return;
        }

        window.clearTimeout(resetTimer);
        button.classList.remove('is-copied', 'is-failed');

        try {
          await copyWithFallback(target.textContent.trim());
          button.textContent = 'Copied';
          button.classList.add('is-copied');
          if (status) {
            status.textContent = 'Code copied to clipboard.';
          }
        } catch (_error) {
          button.textContent = 'Failed';
          button.classList.add('is-failed');
          if (status) {
            status.textContent = 'Unable to copy code. Select it manually.';
          }
        }

        resetTimer = window.setTimeout(function () {
          button.textContent = 'Copy';
          button.classList.remove('is-copied', 'is-failed');
        }, 2200);
      });
    });
  }

  function init() {
    initNavigation();
    initActiveNavigation();
    initTerminalSequence();
    initRevealAnimations();
    initCopyButtons();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
