
// static/tasks_list.js
document.addEventListener('DOMContentLoaded', () => {
  // OPEN add modal (top button) -> focus first inline input (recently_assigned)
  const openAddBtn = document.getElementById('openAddBtn');
  if (openAddBtn) {
    openAddBtn.addEventListener('click', () => {
      const input = document.querySelector('.inline-input[data-section="recently_assigned"]');
      if (input) {
        input.focus();
        window.scrollTo({ top: input.getBoundingClientRect().top + window.scrollY - 120, behavior: 'smooth' });
      }
    });
  }

  // SECTION TOGGLE: collapse/expand
  document.querySelectorAll('.section-toggle').forEach(btn => {
    btn.addEventListener('click', () => {
      const section = btn.closest('.section-block');
      const body = section.querySelector('.section-body');
      const expanded = btn.getAttribute('aria-expanded') === 'true';
      btn.textContent = expanded ? '▸' : '▾';
      btn.setAttribute('aria-expanded', (!expanded).toString());
      if (expanded) body.style.display = 'none'; else body.style.display = '';
    });
  });

  // Inline add button handler
  document.querySelectorAll('.inline-add-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const section = btn.dataset.section;
      const input = document.querySelector(`.inline-input[data-section="${section}"]`);
      const title = input.value && input.value.trim();
      if (!title) return alert('Please enter a task title.');

      // Minimal payload - the server's /api/add_task accepts project_id or creates new
      const payload = {
        title: title,
        description: '',
        project_id: null,
        new_project_title: null,
        assignee_id: null,
        due_date: null,
        priority: 'Medium',
        status: 'todo',
        section: section
      };

      try {
        const res = await fetch('/api/add_task', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
          credentials: 'same-origin'
        });
        const data = await res.json();
        if (res.ok && data.success) {
          // successful: reload the page to get updated grouping (keeps server-side mapping)
          window.location.reload();
        } else {
          alert('Failed to create task: ' + (data.error || 'unknown'));
        }
      } catch (e) {
        console.error(e);
        alert('Network error while adding task.');
      }
    });
  });

  // Press Enter on inline input triggers add button
  document.querySelectorAll('.inline-input').forEach(inp => {
    inp.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        const section = inp.dataset.section;
        const btn = document.querySelector(`.inline-add-btn[data-section="${section}"]`);
        if (btn) btn.click();
      }
    });
  });
});
